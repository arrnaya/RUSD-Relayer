import { ethers, Contract, Wallet, JsonRpcProvider, TransactionResponse } from 'ethers';
import { config as dotenvConfig } from 'dotenv';
import * as fs from 'fs';
import * as path from 'path';
import * as winston from 'winston';

// Load environment variables
dotenvConfig();

// Logger setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'relayer.log' }),
    new winston.transports.Console()
  ]
});

// TokenBridge contract ABI
const TOKEN_BRIDGE_ABI = [
  // Events
  'event MessageSent(bytes32 indexed messageId, address indexed sender, address indexed target, bytes data, uint256 nonce)',
  'event MessageReceived(bytes32 indexed messageId, address indexed sender, address indexed target, bytes data, uint256 nonce)',
  'event TokensLocked(bytes32 indexed messageId, address indexed sender, address indexed recipient, address localToken, address remoteToken, uint256 value, uint256 nonce)',
  'event FailedMessageFixed(bytes32 indexed messageId, address indexed recipient, address tokenAddress, uint256 value)',
  // Functions
  'function receiveMessage(bytes32 messageId, address sender, address target, bytes calldata data) external',
  'function fixFailedMessage(bytes32 messageId) external',
  'function isMessageProcessed(bytes32 messageId) external view returns (bool)',
  'function isMessageFixed(bytes32 messageId) external view returns (bool)',
  'function remoteTokenBridge() external view returns (address)',
  'function initialized() external view returns (bool)',
  'function hasRole(bytes32 role, address account) external view returns (bool)',
  'function paused() external view returns (bool)'
];

// Interface for handleBridgedTokens
const HANDLE_BRIDGED_TOKENS_ABI = [
  'function handleBridgedTokens(address recipient, address token, uint256 value, uint256 nonce) external'
];
const handleBridgedTokensInterface = new ethers.Interface(HANDLE_BRIDGED_TOKENS_ABI);

// Configuration interfaces
interface ChainConfig {
  chainId: number;
  rpcUrl: string;
  fallbackRpcUrl?: string;
  tokenBridgeAddress: string;
  remoteChainId: number;
}

interface RelayerConfig {
  privateKey: string;
  chains: ChainConfig[];
}

// Load configuration
const configPath = path.resolve(__dirname, 'relayer.config.json');
const config: RelayerConfig = JSON.parse(fs.readFileSync(configPath, 'utf-8'));

// Validate configuration
if (!config.privateKey || config.chains.length !== 2) {
  logger.error('Invalid configuration: privateKey and exactly two chains are required');
  process.exit(1);
}

// Queue for failed messages
const queueFile = path.resolve(__dirname, 'failedMessages.json');
const saveFailedMessage = (chainId: number, messageId: string) => {
  const queue = fs.existsSync(queueFile) ? JSON.parse(fs.readFileSync(queueFile, 'utf-8')) : [];
  queue.push({ chainId, messageId, timestamp: Date.now() });
  fs.writeFileSync(queueFile, JSON.stringify(queue));
};

// Relayer class
class Relayer {
  private wallets: Map<number, Wallet> = new Map();
  private providers: Map<number, JsonRpcProvider> = new Map();
  private tokenBridgeContracts: Map<number, Contract> = new Map();
  private chainConfigs: Map<number, ChainConfig> = new Map();
  private isRunning: boolean = false;
  private processingMessages: Set<string> = new Set(); // Track messages being processed

  constructor() { }

  public async initialize() {
    logger.info('Starting initialization...');
    for (const chain of config.chains) {
      try {
        logger.info(`Initializing chain ${chain.chainId}...`);
        let provider = new JsonRpcProvider(chain.rpcUrl);

        // Test provider connectivity
        try {
          await provider.getNetwork();
          logger.info(`Connected to RPC for chain ${chain.chainId}: ${chain.rpcUrl}`);
        } catch (error: any) {
          logger.warn(`Primary RPC failed for chain ${chain.chainId}: ${error.message}`);
          if (chain.fallbackRpcUrl) {
            logger.info(`Switching to fallback RPC: ${chain.fallbackRpcUrl}`);
            provider = new JsonRpcProvider(chain.fallbackRpcUrl);
            await provider.getNetwork();
            logger.info(`Connected to fallback RPC for chain ${chain.chainId}: ${chain.fallbackRpcUrl}`);
          } else {
            throw new Error(`No fallback RPC available for chain ${chain.chainId}`);
          }
        }

        const wallet = new Wallet(config.privateKey, provider);
        const tokenBridgeContract = new Contract(chain.tokenBridgeAddress, TOKEN_BRIDGE_ABI, wallet);

        // Validate contract state
        const initialized = await tokenBridgeContract.initialized();
        if (!initialized) {
          logger.error(`TokenBridge contract on chain ${chain.chainId} is not initialized`);
          throw new Error('TokenBridge contract not initialized');
        }

        const remoteTokenBridge = await tokenBridgeContract.remoteTokenBridge();
        const expectedRemoteTokenBridge = config.chains.find(c => c.chainId === chain.remoteChainId)?.tokenBridgeAddress;
        if (remoteTokenBridge.toLowerCase() !== expectedRemoteTokenBridge?.toLowerCase()) {
          logger.error(`TokenBridge on chain ${chain.chainId} has incorrect remoteTokenBridge: expected ${expectedRemoteTokenBridge}, got ${remoteTokenBridge}`);
          throw new Error('Incorrect remoteTokenBridge');
        }

        const hasRelayerRole = await tokenBridgeContract.hasRole(ethers.id('RELAYER_ROLE'), wallet.address);
        if (!hasRelayerRole) {
          logger.error(`Wallet ${wallet.address} does not have RELAYER_ROLE on chain ${chain.chainId}`);
          throw new Error('Missing RELAYER_ROLE');
        }

        const isPaused = await tokenBridgeContract.paused();
        if (isPaused) {
          logger.error(`TokenBridge contract on chain ${chain.chainId} is paused`);
          throw new Error('TokenBridge contract paused');
        }

        this.providers.set(chain.chainId, provider);
        this.wallets.set(chain.chainId, wallet);
        this.tokenBridgeContracts.set(chain.chainId, tokenBridgeContract);
        this.chainConfigs.set(chain.chainId, chain);

        logger.info(`Initialized chain ${chain.chainId}: TokenBridge at ${chain.tokenBridgeAddress}`);
      } catch (error: any) {
        logger.error(`Failed to initialize chain ${chain.chainId}: ${error.message}`);
        throw error;
      }
    }
    logger.info('Initialization complete');
  }

  public async start() {
    if (this.isRunning) {
      logger.warn('Relayer is already running');
      return;
    }

    this.isRunning = true;
    logger.info('Starting relayer...');

    try {
      logger.info('Setting up event listeners...');
      for (const [chainId, tokenBridgeContract] of this.tokenBridgeContracts) {
        logger.info(`Processing chain ${chainId} for event listener setup`);
        await this.setupEventListener(chainId, tokenBridgeContract);
      }
      logger.info('All event listeners set up');
    } catch (error: any) {
      logger.error(`Failed to set up event listeners: ${error.message}`);
      throw error;
    }

    process.on('SIGINT', this.shutdown.bind(this));
    process.on('SIGTERM', this.shutdown.bind(this));
  }

  private async setupEventListener(chainId: number, tokenBridgeContract: Contract) {
    logger.info(`Setting up event listener for chain ${chainId}`);

    const provider = this.providers.get(chainId);
    if (!provider) {
      logger.error(`Provider not found for chain ${chainId}`);
      throw new Error(`Provider not found for chain ${chainId}`);
    }

    const chainConfig = this.chainConfigs.get(chainId);
    if (!chainConfig) {
      logger.error(`Chain configuration not found for chain ${chainId}`);
      throw new Error(`Chain configuration not found for chain ${chainId}`);
    }

    // Function to process MessageSent events
    const processMessageSent = async (
      messageId: string,
      sender: string,
      target: string,
      data: string,
      nonce: bigint,
      event: ethers.EventLog // Explicitly type as EventLog
    ) => {
      // Prevent concurrent processing of the same message
      if (this.processingMessages.has(messageId)) {
        logger.warn(`Message ${messageId} is already being processed on chain ${chainId}`);
        return;
      }
      this.processingMessages.add(messageId);

      try {
        logger.info(
          `Detected MessageSent on chain ${chainId}: messageId=${messageId}, sender=${sender}, target=${target}, nonce=${nonce}, data=${data}`
        );

        const sourceChainConfig = this.chainConfigs.get(chainId);
        if (!sourceChainConfig) {
          logger.error(`No configuration found for chain ${chainId}`);
          return;
        }

        const destChainId = sourceChainConfig.remoteChainId;
        let destTokenBridgeContract = this.tokenBridgeContracts.get(destChainId);
        let destProvider = this.providers.get(destChainId);
        let destWallet = this.wallets.get(destChainId);
        const destChainConfig = this.chainConfigs.get(destChainId);

        if (!destTokenBridgeContract || !destProvider || !destWallet || !destChainConfig) {
          logger.error(`Destination chain ${destChainId} not initialized`);
          return;
        }

        const isProcessed = await destTokenBridgeContract.isMessageProcessed(messageId);
        if (isProcessed) {
          logger.warn(`Message ${messageId} already processed on chain ${destChainId}`);
          return;
        }

        const sourceTokenBridgeAddress = sourceChainConfig.tokenBridgeAddress;
        if (!sourceTokenBridgeAddress) {
          logger.error(`Source TokenBridge address not found for chain ${chainId}`);
          return;
        }

        if (!data || data === '0x') {
          logger.error(`Invalid or empty data for message ${messageId} on chain ${destChainId}`);
          await this.handleFailedMessage(chainId, messageId);
          return;
        }

        // Validate data (expecting handleBridgedTokens)
        try {
          const decodedData = handleBridgedTokensInterface.parseTransaction({ data });
          if (!decodedData || decodedData.name !== 'handleBridgedTokens') {
            logger.error(`Invalid data for message ${messageId}: not a handleBridgedTokens call`);
            await this.handleFailedMessage(chainId, messageId);
            return;
          }
          const { recipient, token, value, nonce: dataNonce } = decodedData.args;
          logger.info(
            `Decoded handleBridgedTokens: recipient=${recipient}, token=${token}, value=${value.toString()}, nonce=${dataNonce.toString()}`
          );
          if (dataNonce !== nonce) {
            logger.error(
              `Nonce mismatch for message ${messageId}: event nonce=${nonce}, data nonce=${dataNonce}`
            );
            await this.handleFailedMessage(chainId, messageId);
            return;
          }
        } catch (error: any) {
          logger.error(`Failed to decode data for message ${messageId}: ${error.message}`);
          await this.handleFailedMessage(chainId, messageId);
          return;
        }

        // Validate remoteTokenBridge
        const remoteTokenBridge = await destTokenBridgeContract.remoteTokenBridge();
        if (remoteTokenBridge.toLowerCase() !== sourceTokenBridgeAddress.toLowerCase()) {
          logger.error(
            `Invalid remoteTokenBridge for chain ${destChainId}: expected ${sourceTokenBridgeAddress}, got ${remoteTokenBridge}`
          );
          await this.handleFailedMessage(chainId, messageId);
          return;
        }

        // Validate target
        if (target.toLowerCase() !== destChainConfig.tokenBridgeAddress.toLowerCase()) {
          logger.error(
            `Invalid target for message ${messageId}: target=${target}, expected ${destChainConfig.tokenBridgeAddress}`
          );
          await this.handleFailedMessage(chainId, messageId);
          return;
        }

        let gasLimit: bigint;
        try {
          gasLimit = await destTokenBridgeContract.receiveMessage.estimateGas(
            messageId,
            sourceTokenBridgeAddress,
            target,
            data
          );
          gasLimit = (gasLimit * BigInt(150)) / BigInt(100); // 50% buffer
        } catch (error: any) {
          logger.error(
            `Failed to estimate gas for message ${messageId} on chain ${destChainId}: ${error.message}`,
            {
              revertData: error.data,
              reason: error.reason,
            }
          );
          if (error.reason?.includes('ReentrancyGuard: reentrant call')) {
            logger.warn(`Reentrancy detected for message ${messageId}, queuing for later retry`);
            saveFailedMessage(chainId, messageId);
          }
          await this.handleFailedMessage(chainId, messageId);
          return;
        }

        logger.info(`Relaying message ${messageId} to chain ${destChainId} with gasLimit ${gasLimit}`);
        let attempts = 0;
        const maxAttempts = 5;
        const initialDelay = 10000; // 10 seconds
        while (attempts < maxAttempts) {
          try {
            const tx: TransactionResponse = await destTokenBridgeContract.receiveMessage(
              messageId,
              sourceTokenBridgeAddress,
              target,
              data,
              { gasLimit }
            );

            logger.info(`Transaction sent: ${tx.hash}`);
            const receipt = await tx.wait();

            if (receipt?.status === 1) {
              logger.info(
                `Message ${messageId} successfully relayed to chain ${destChainId}: tx=${tx.hash}`
              );
              return;
            } else {
              logger.error(
                `Message ${messageId} relay failed: tx=${tx.hash}, receipt=${JSON.stringify(receipt)}`
              );
              break;
            }
          } catch (error: any) {
            attempts++;
            const delay = initialDelay * Math.pow(2, attempts); // 10s, 20s, 40s, 80s, 160s
            logger.warn(`Retry ${attempts}/${maxAttempts} for message ${messageId}: ${error.message}`, {
              revertData: error.data,
            });
            if (
              error.info?.responseStatus?.includes('429 Too Many Requests') &&
              attempts === 3 &&
              destChainConfig.fallbackRpcUrl
            ) {
              logger.info(
                `Switching to fallback RPC for chain ${destChainId}: ${destChainConfig.fallbackRpcUrl}`
              );
              const newProvider = new JsonRpcProvider(destChainConfig.fallbackRpcUrl);
              this.providers.set(destChainId, newProvider);
              destWallet = new Wallet(config.privateKey, newProvider);
              this.wallets.set(destChainId, destWallet);
              destTokenBridgeContract = new Contract(
                destChainConfig.tokenBridgeAddress,
                TOKEN_BRIDGE_ABI,
                destWallet
              );
              this.tokenBridgeContracts.set(destChainId, destTokenBridgeContract);
            }
            if (attempts === maxAttempts) {
              logger.error(`Max retries reached for message ${messageId}`);
              await this.handleFailedMessage(chainId, messageId);
              break;
            }
            await new Promise((resolve) => setTimeout(resolve, delay));
          }
        }
      } catch (error: any) {
        logger.error(`Error processing MessageSent for messageId ${messageId}: ${error.message}`, {
          error: JSON.stringify(error),
          transaction: error.transaction,
          receipt: error.receipt,
          revertData: error.data,
        });
        await this.handleFailedMessage(chainId, messageId);
      } finally {
        this.processingMessages.delete(messageId);
        // Add a short delay to avoid rapid concurrent processing
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    };

    // Function to set up or refresh the event listener
    const setupFilter = async () => {
      try {
        // Remove existing listeners to avoid duplicates
        tokenBridgeContract.removeAllListeners('MessageSent');

        // Set up the event listener
        tokenBridgeContract.on('MessageSent', processMessageSent);
        logger.info(`Event listener (filter) active for chain ${chainId}`);

        // Handle provider errors (e.g., filter not found)
        provider.on('error', async (error: any) => {
          if (
            error?.error?.message?.includes('filter not found') ||
            error?.message?.includes('filter not found')
          ) {
            logger.warn(
              `Filter not found for chain ${chainId}, recreating filter: ${JSON.stringify(error)}`
            );
            await setupFilter(); // Recreate the filter
          } else {
            logger.error(`Provider error for chain ${chainId}: ${JSON.stringify(error)}`);
          }
        });
      } catch (error: any) {
        logger.error(`Failed to set up filter for chain ${chainId}: ${error.message}`);
        throw error;
      }
    };

    // Function to poll for events as a fallback
    const startPolling = async () => {
      const POLLING_INTERVAL = 60000; // Poll every 60 seconds
      let lastBlockProcessed = await provider.getBlockNumber();

      const pollEvents = async () => {
        try {
          const currentBlock = await provider.getBlockNumber();
          if (currentBlock <= lastBlockProcessed) {
            return; // No new blocks to process
          }

          logger.info(
            `Polling for MessageSent events on chain ${chainId} from block ${lastBlockProcessed + 1} to ${currentBlock}`
          );

          const filter = tokenBridgeContract.filters.MessageSent();
          const events = await tokenBridgeContract.queryFilter(
            filter,
            lastBlockProcessed + 1,
            currentBlock
          );

          for (const event of events) {
            let args;
            if ('args' in event) {
              args = event.args; // EventLog case
            } else {
              // Decode Log manually
              const parsedLog = tokenBridgeContract.interface.parseLog(event);
              if (!parsedLog) {
                logger.error(`Failed to parse log for event on chain ${chainId}`);
                continue;
              }
              args = parsedLog.args;
            }
            const { messageId, sender, target, data, nonce } = args;
            await processMessageSent(messageId, sender, target, data, nonce, event as ethers.EventLog);
          }

          lastBlockProcessed = currentBlock;
        } catch (error: any) {
          logger.error(`Polling error on chain ${chainId}: ${error.message}`);
          if (
            error?.error?.message?.includes('filter not found') ||
            error?.message?.includes('filter not found')
          ) {
            logger.warn(`Filter not found during polling, recreating filter`);
            await setupFilter();
          }
        }
      };

      // Run polling loop
      const pollingLoop = async () => {
        while (this.isRunning) {
          await pollEvents();
          await new Promise((resolve) => setTimeout(resolve, POLLING_INTERVAL));
        }
      };

      pollingLoop().catch((error) => {
        logger.error(`Polling loop crashed on chain ${chainId}: ${error.message}`);
        // Restart polling after a delay
        setTimeout(() => startPolling(), 10000);
      });
    };

    try {
      // Set up the initial filter
      await setupFilter();

      // Start polling as a fallback
      await startPolling();

      // Switch to fallback RPC if primary RPC fails consistently
      let rpcFailureCount = 0;
      const maxRpcFailures = 5;
      provider.on('error', async (error: any) => {
        if (
          error?.info?.responseStatus?.includes('429 Too Many Requests') ||
          error?.message?.includes('connection')
        ) {
          rpcFailureCount++;
          logger.warn(
            `RPC failure ${rpcFailureCount}/${maxRpcFailures} for chain ${chainId}: ${JSON.stringify(
              error
            )}`
          );

          if (rpcFailureCount >= maxRpcFailures && chainConfig.fallbackRpcUrl) {
            logger.info(`Switching to fallback RPC for chain ${chainId}: ${chainConfig.fallbackRpcUrl}`);
            const newProvider = new JsonRpcProvider(chainConfig.fallbackRpcUrl);
            this.providers.set(chainId, newProvider);
            const newWallet = new Wallet(config.privateKey, newProvider);
            this.wallets.set(chainId, newWallet);
            const newTokenBridgeContract = new Contract(
              chainConfig.tokenBridgeAddress,
              TOKEN_BRIDGE_ABI,
              newWallet
            );
            this.tokenBridgeContracts.set(chainId, newTokenBridgeContract);

            // Reset failure count and set up listener on new provider
            rpcFailureCount = 0;
            await setupFilter();
            logger.info(`Switched to fallback RPC and recreated listener for chain ${chainId}`);
          }
        }
      });
    } catch (error: any) {
      logger.error(`Failed to set up event listener for chain ${chainId}: ${error.message}`);
      throw error;
    }
  }

  private async handleFailedMessage(chainId: number, messageId: string) {
    try {
      logger.info(`Handling failed message ${messageId} on source chain ${chainId}`);

      let sourceTokenBridgeContract = this.tokenBridgeContracts.get(chainId);
      let sourceProvider = this.providers.get(chainId);
      let sourceWallet = this.wallets.get(chainId);
      const sourceChainConfig = this.chainConfigs.get(chainId);

      if (!sourceTokenBridgeContract || !sourceProvider || !sourceWallet || !sourceChainConfig) {
        logger.error(`Source chain ${chainId} not initialized for fixing message ${messageId}`);
        saveFailedMessage(chainId, messageId);
        return;
      }

      const isFixed = await sourceTokenBridgeContract.isMessageFixed(messageId);
      if (isFixed) {
        logger.warn(`Message ${messageId} already fixed on chain ${chainId}`);
        return;
      }

      const isProcessed = await sourceTokenBridgeContract.isMessageProcessed(messageId);
      if (isProcessed) {
        logger.warn(`Message ${messageId} was processed, cannot fix on chain ${chainId}`);
        return;
      }

      let gasLimit: bigint;
      try {
        gasLimit = await sourceTokenBridgeContract.fixFailedMessage.estimateGas(messageId);
        gasLimit = gasLimit * BigInt(150) / BigInt(100); // 50% buffer
      } catch (error: any) {
        logger.error(`Failed to estimate gas for fixFailedMessage ${messageId} on chain ${chainId}: ${error.message}`);
        saveFailedMessage(chainId, messageId);
        return;
      }

      let attempts = 0;
      const maxAttempts = 5;
      const initialDelay = 10000; // 10 seconds
      while (attempts < maxAttempts) {
        try {
          const tx: TransactionResponse = await sourceTokenBridgeContract.fixFailedMessage(messageId, { gasLimit });
          logger.info(`fixFailedMessage transaction sent for message ${messageId}: ${tx.hash}`);

          const receipt = await tx.wait();
          if (receipt?.status === 1) {
            logger.info(`Message ${messageId} successfully fixed on chain ${chainId}: tx=${tx.hash}`);
            return;
          } else {
            logger.error(`fixFailedMessage failed for message ${messageId}: tx=${tx.hash}, receipt=${JSON.stringify(receipt)}`);
            saveFailedMessage(chainId, messageId);
            return;
          }
        } catch (error: any) {
          attempts++;
          const delay = initialDelay * Math.pow(2, attempts); // 10s, 20s, 40s, 80s, 160s
          logger.warn(`Retry ${attempts}/${maxAttempts} for fixFailedMessage ${messageId}: ${error.message}`, {
            revertData: error.data
          });
          if (error.info?.responseStatus?.includes('429 Too Many Requests') && attempts === 3 && sourceChainConfig.fallbackRpcUrl) {
            logger.info(`Switching to fallback RPC for chain ${chainId}: ${sourceChainConfig.fallbackRpcUrl}`);
            const newProvider = new JsonRpcProvider(sourceChainConfig.fallbackRpcUrl);
            this.providers.set(chainId, newProvider);
            sourceWallet = new Wallet(config.privateKey, newProvider);
            this.wallets.set(chainId, sourceWallet);
            sourceTokenBridgeContract = new Contract(sourceChainConfig.tokenBridgeAddress, TOKEN_BRIDGE_ABI, sourceWallet);
            this.tokenBridgeContracts.set(chainId, sourceTokenBridgeContract);
          }
          if (attempts === maxAttempts) {
            logger.error(`Max retries reached for fixFailedMessage ${messageId}`);
            saveFailedMessage(chainId, messageId);
            logger.info(`Queued message ${messageId} for later retry`);
            return;
          }
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    } catch (error: any) {
      logger.error(`Failed to fix message ${messageId} on chain ${chainId}: ${error.message}`, {
        revertData: error.data
      });
      saveFailedMessage(chainId, messageId);
    }
  }

  private async shutdown() {
    if (!this.isRunning) return;

    logger.info('Shutting down relayer...');
    this.isRunning = false;

    for (const [chainId, tokenBridgeContract] of this.tokenBridgeContracts) {
      tokenBridgeContract.removeAllListeners();
      logger.info(`Removed listeners for chain ${chainId}`);
    }

    for (const [chainId, provider] of this.providers) {
      provider.removeAllListeners();
      logger.info(`Disconnected provider for chain ${chainId}`);
    }

    process.exit(0);
  }
}

// Start the relayer
async function main() {
  try {
    logger.info('Creating Relayer instance...');
    const relayer = new Relayer();
    logger.info('Initializing Relayer...');
    await relayer.initialize();
    logger.info('Starting Relayer...');
    await relayer.start();
  } catch (error: any) {
    logger.error(`Relayer failed to start: ${error.message}`, { error: JSON.stringify(error) });
    process.exit(1);
  }
}

main().catch((error) => {
  logger.error(`Main function failed: ${error.message}`, { error: JSON.stringify(error) });
  process.exit(1);
});