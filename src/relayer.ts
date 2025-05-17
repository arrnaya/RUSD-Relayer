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
  'event MessageSent(bytes32 indexed messageId, address indexed sender, address indexed target, bytes data, uint256 nonce)',
  'event MessageReceived(bytes32 indexed messageId, address indexed sender, address indexed target, bytes data, uint256 nonce)',
  'event TokensLocked(bytes32 indexed messageId, address indexed sender, address indexed recipient, address localToken, address remoteToken, uint256 value, uint256 nonce)',
  'event FailedMessageFixed(bytes32 indexed messageId, address indexed recipient, address tokenAddress, uint256 value)',
  'function receiveMessage(bytes32 messageId, uint64 chainId, address sender, address target, bytes calldata data) external',
  'function fixFailedMessage(bytes32 messageId) external',
  'function isMessageProcessed(bytes32 messageId) external view returns (bool)',
  'function isMessageFixed(bytes32 messageId) external view returns (bool)',
  'function getRemoteTokenBridge(uint64 chainId) external view returns (address)',
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
  pollingIntervalMs?: number; // Polling interval in ms
  gasLimitBufferPercent?: number; // Gas limit buffer percentage
}

interface RelayerConfig {
  privateKey: string;
  chains: ChainConfig[];
  maxRetries?: number; // Max transaction retries
  failedMessageTtlMs?: number; // TTL for failed messages
  rateLimitBackoffMs?: number; // Initial backoff for 429 errors
}

// Load configuration
const configPath = path.resolve(__dirname, 'relayer.config.json');
const config: RelayerConfig = JSON.parse(fs.readFileSync(configPath, 'utf-8'));

// Validate configuration
if (!config.privateKey || config.chains.length < 1) {
  logger.error('Invalid configuration: privateKey and at least one chain are required');
  process.exit(1);
}
for (const chain of config.chains) {
  if (!chain.tokenBridgeAddress || !chain.remoteChainId || !config.chains.some(c => c.chainId === chain.remoteChainId)) {
    logger.error(`Invalid configuration for chain ${chain.chainId}: missing tokenBridgeAddress, remoteChainId, or invalid remoteChainId`);
    process.exit(1);
  }
}

// Queue for failed messages
const queueFile = path.resolve(__dirname, 'failedMessages.json');
const saveFailedMessage = (chainId: number, messageId: string) => {
  const queue = fs.existsSync(queueFile) ? JSON.parse(fs.readFileSync(queueFile, 'utf-8')) : [];
  if (!queue.some((entry: any) => entry.chainId === chainId && entry.messageId === messageId)) {
    queue.push({ chainId, messageId, timestamp: Date.now() });
    fs.writeFileSync(queueFile, JSON.stringify(queue));
  }
};

// Relayer class
class Relayer {
  private wallets: Map<number, Wallet> = new Map();
  private providers: Map<number, JsonRpcProvider> = new Map();
  private tokenBridgeContracts: Map<number, Contract> = new Map();
  private chainConfigs: Map<number, ChainConfig> = new Map();
  private isRunning: boolean = false;
  private processingMessages: Set<string> = new Set();
  private maxRetries: number = config.maxRetries || 3;
  private failedMessageTtlMs: number = config.failedMessageTtlMs || 24 * 60 * 60 * 1000;
  private rateLimitBackoffMs: number = config.rateLimitBackoffMs || 60000; // 1 minute initial backoff
  private rateLimitBackoff: Map<number, number> = new Map(); // Track backoff per chain

  constructor() { }

  public async initialize() {
    logger.info('Starting initialization...');
    for (const chain of config.chains) {
      try {
        logger.info(`Initializing chain ${chain.chainId}...`);
        let provider = new JsonRpcProvider(chain.rpcUrl);

        // Validate chain ID
        const network = await provider.getNetwork();
        if (Number(network.chainId) !== chain.chainId) {
          logger.error(`Chain ID mismatch for chain ${chain.chainId}: expected ${chain.chainId}, got ${network.chainId}`);
          throw new Error('Chain ID mismatch');
        }
        logger.info(`Connected to RPC for chain ${chain.chainId}: ${chain.rpcUrl}`);

        const wallet = new Wallet(config.privateKey, provider);
        const tokenBridgeContract = new Contract(chain.tokenBridgeAddress, TOKEN_BRIDGE_ABI, wallet);

        // Batch contract state checks
        const [initialized, remoteTokenBridge, hasRelayerRole, isPaused] = await Promise.all([
          tokenBridgeContract.initialized(),
          tokenBridgeContract.getRemoteTokenBridge(chain.remoteChainId),
          tokenBridgeContract.hasRole(ethers.id('RELAYER_ROLE'), wallet.address),
          tokenBridgeContract.paused()
        ]);

        if (!initialized) {
          logger.error(`TokenBridge contract on chain ${chain.chainId} is not initialized`);
          throw new Error('TokenBridge contract not initialized');
        }

        const expectedRemoteTokenBridge = config.chains.find(c => c.chainId === chain.remoteChainId)?.tokenBridgeAddress;
        if (remoteTokenBridge.toLowerCase() !== expectedRemoteTokenBridge?.toLowerCase()) {
          logger.error(`TokenBridge on chain ${chain.chainId} has incorrect remoteTokenBridge: expected ${expectedRemoteTokenBridge}, got ${remoteTokenBridge}`);
          throw new Error('Incorrect remoteTokenBridge');
        }

        if (!hasRelayerRole) {
          logger.error(`Wallet ${wallet.address} does not have RELAYER_ROLE on chain ${chain.chainId}`);
          throw new Error('Missing RELAYER_ROLE');
        }

        if (isPaused) {
          logger.error(`TokenBridge contract on chain ${chain.chainId} l is paused`);
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

    // Start failed message retry loop (every 12 hours for low usage)
    setInterval(() => this.retryFailedMessages(), 12 * 60 * 60 * 1000);

    for (const [chainId, tokenBridgeContract] of this.tokenBridgeContracts) {
      await this.setupEventListener(chainId, tokenBridgeContract);
    }

    process.on('SIGINT', this.shutdown.bind(this));
    process.on('SIGTERM', this.shutdown.bind(this));
  }

  private async setupEventListener(chainId: number, tokenBridgeContract: Contract) {
    logger.info(`Setting up event listener for chain ${chainId}`);
    const provider = this.providers.get(chainId);
    const chainConfig = this.chainConfigs.get(chainId);
    if (!provider || !chainConfig) {
      logger.error(`Provider or config not found for chain ${chainId}`);
      throw new Error(`Setup failed for chain ${chainId}`);
    }

    const processMessageSent = async (
      messageId: string,
      sender: string,
      target: string,
      data: string,
      nonce: bigint,
      event: ethers.EventLog
    ) => {
      if (this.processingMessages.has(messageId)) {
        logger.warn(`Message ${messageId} is already being processed on chain ${chainId}`);
        return;
      }
      this.processingMessages.add(messageId);

      try {
        logger.info(`Detected MessageSent on chain ${chainId}: messageId=${messageId}, sender=${sender}, target=${target}, nonce=${nonce}`);

        const destChainId = chainConfig.remoteChainId;
        const destTokenBridgeContract = this.tokenBridgeContracts.get(destChainId);
        const destChainConfig = this.chainConfigs.get(destChainId);
        if (!destTokenBridgeContract || !destChainConfig) {
          logger.error(`Destination chain ${destChainId} not initialized`);
          return;
        }

        // Check if destination contract is paused
        if (await destTokenBridgeContract.paused()) {
          logger.warn(`Destination contract on chain ${destChainId} is paused, queuing message ${messageId}`);
          saveFailedMessage(chainId, messageId);
          return;
        }

        const isProcessed = await destTokenBridgeContract.isMessageProcessed(messageId);
        if (isProcessed) {
          logger.warn(`Message ${messageId} already processed on chain ${destChainId}`);
          return;
        }

        if (!data || data === '0x' || data.length < 4) {
          logger.error(`Invalid data for message ${messageId}: ${data}`);
          await this.handleFailedMessage(chainId, messageId);
          return;
        }

        // Decode and validate data
        let decodedData;
        try {
          decodedData = handleBridgedTokensInterface.parseTransaction({ data });
          if (!decodedData || decodedData.name !== 'handleBridgedTokens') {
            logger.error(`Invalid data for message ${messageId}: not a handleBridgedTokens call`);
            await this.handleFailedMessage(chainId, messageId);
            return;
          }
        } catch (error: any) {
          logger.error(`Failed to decode data for message ${messageId}: ${error.message}`);
          await this.handleFailedMessage(chainId, messageId);
          return;
        }

        // Validate target
        if (target.toLowerCase() !== destChainConfig.tokenBridgeAddress.toLowerCase()) {
          logger.error(`Invalid target for message ${messageId}: expected ${destChainConfig.tokenBridgeAddress}, got ${target}`);
          await this.handleFailedMessage(chainId, messageId);
          return;
        }

        let gasLimit: bigint;
        try {
          gasLimit = await destTokenBridgeContract.receiveMessage.estimateGas(
            messageId,
            chainId,
            chainConfig.tokenBridgeAddress,
            target,
            data
          );
          const bufferPercent = chainConfig.gasLimitBufferPercent || 20;
          gasLimit = (gasLimit * BigInt(100 + bufferPercent)) / BigInt(100);
        } catch (error: any) {
          logger.error(`Failed to estimate gas for message ${messageId}: ${error.message}`);
          if (error.reason?.includes('ReentrancyGuard: reentrant call')) {
            saveFailedMessage(chainId, messageId);
          }
          await this.handleFailedMessage(chainId, messageId);
          return;
        }

        let attempts = 0;
        const initialDelay = 10000;
        while (attempts < this.maxRetries) {
          try {
            const tx: TransactionResponse = await destTokenBridgeContract.receiveMessage(
              messageId,
              chainId,
              chainConfig.tokenBridgeAddress,
              target,
              data,
              { gasLimit }
            );
            logger.info(`Transaction sent: ${tx.hash}`);
            const receipt = await tx.wait();
            if (receipt?.status === 1) {
              logger.info(`Message ${messageId} relayed to chain ${destChainId}: tx=${tx.hash}`);
              return;
            }
          } catch (error: any) {
            attempts++;
            const delay = initialDelay * Math.pow(2, attempts);
            logger.warn(`Retry ${attempts}/${this.maxRetries} for message ${messageId}: ${error.message}`);
            if (error.message.includes('Too Many Requests') && chainConfig.fallbackRpcUrl) {
              logger.info(`Switching to fallback RPC for chain ${destChainId}: ${chainConfig.fallbackRpcUrl}`);
              await this.switchToFallbackRpc(destChainId);
              return; // Retry with new provider
            }
            if (attempts === this.maxRetries) {
              logger.error(`Max retries reached for message ${messageId}`);
              await this.handleFailedMessage(chainId, messageId);
              break;
            }
            await new Promise(resolve => setTimeout(resolve, delay));
          }
        }
      } finally {
        this.processingMessages.delete(messageId);
      }
    };

    const setupFilter = async () => {
      try {
        tokenBridgeContract.removeAllListeners('MessageSent');
        tokenBridgeContract.on('MessageSent', processMessageSent);
        logger.info(`Event listener active for chain ${chainId}`);
      } catch (error: any) {
        logger.error(`Failed to set up filter for chain ${chainId}: ${error.message}`);
        if (chainConfig.fallbackRpcUrl) {
          logger.info(`Switching to fallback RPC for chain ${chainId}: ${chainConfig.fallbackRpcUrl}`);
          await this.switchToFallbackRpc(chainId);
          await setupFilter();
        } else {
          throw error;
        }
      }
    };

    const startPolling = async () => {
      const pollingInterval = chainConfig.pollingIntervalMs || 600000; // 10 minutes
      let lastBlockProcessed = await provider.getBlockNumber();
      let backoffCount = 0;

      const pollEvents = async () => {
        try {
          // Check for rate limit backoff
          const backoffUntil = this.rateLimitBackoff.get(chainId) || 0;
          if (Date.now() < backoffUntil) {
            logger.debug(`Chain ${chainId} in rate limit backoff until ${new Date(backoffUntil).toISOString()}`);
            return;
          }

          logger.debug(`Polling chain ${chainId}: fetching block number`);
          const currentBlock = await provider.getBlockNumber();
          if (currentBlock <= lastBlockProcessed) {
            logger.debug(`No new blocks on chain ${chainId}: current=${currentBlock}, last=${lastBlockProcessed}`);
            return;
          }

          const maxBlockRange = 50;
          const toBlock = Math.min(currentBlock, lastBlockProcessed + maxBlockRange);
          logger.info(`Polling chain ${chainId} from block ${lastBlockProcessed + 1} to ${toBlock}`);

          const filter = tokenBridgeContract.filters.MessageSent();
          const events = await tokenBridgeContract.queryFilter(filter, lastBlockProcessed + 1, toBlock);
          logger.debug(`Found ${events.length} MessageSent events on chain ${chainId}`);

          for (const event of events) {
            const args = 'args' in event ? event.args : tokenBridgeContract.interface.parseLog(event)?.args;
            if (!args) continue;
            const { messageId, sender, target, data, nonce } = args;
            await processMessageSent(messageId, sender, target, data, nonce, event as ethers.EventLog);
          }

          lastBlockProcessed = toBlock;
          backoffCount = 0; // Reset backoff on success
        } catch (error: any) {
          logger.error(`Polling error on chain ${chainId}: ${error.message}`);
          if (error.message.includes('Too Many Requests') || error.code === -32005) {
            backoffCount++;
            const backoffMs = this.rateLimitBackoffMs * Math.pow(2, backoffCount - 1);
            const backoffUntil = Date.now() + backoffMs;
            this.rateLimitBackoff.set(chainId, backoffUntil);
            logger.warn(`Rate limit hit on chain ${chainId}, backing off for ${backoffMs / 1000}s until ${new Date(backoffUntil).toISOString()}`);
            if (chainConfig.fallbackRpcUrl) {
              logger.info(`Switching to fallback RPC for chain ${chainId}: ${chainConfig.fallbackRpcUrl}`);
              await this.switchToFallbackRpc(chainId);
            }
          }
        }
      };

      while (this.isRunning) {
        await pollEvents();
        await new Promise(resolve => setTimeout(resolve, pollingInterval));
      }
    };

    await setupFilter();
    startPolling().catch(error => {
      logger.error(`Polling loop crashed on chain ${chainId}: ${error.message}`);
      setTimeout(() => startPolling(), 60000);
    });
  }

  private async switchToFallbackRpc(chainId: number) {
    const chainConfig = this.chainConfigs.get(chainId);
    if (!chainConfig?.fallbackRpcUrl) {
      logger.error(`No fallback RPC available for chain ${chainId}`);
      return;
    }

    try {
      const provider = new JsonRpcProvider(chainConfig.fallbackRpcUrl);
      const network = await provider.getNetwork();
      if (Number(network.chainId) !== chainId) {
        logger.error(`Fallback RPC chain ID mismatch for chain ${chainId}: got ${network.chainId}`);
        return;
      }

      const wallet = new Wallet(config.privateKey, provider);
      const tokenBridgeContract = new Contract(chainConfig.tokenBridgeAddress, TOKEN_BRIDGE_ABI, wallet);

      this.providers.set(chainId, provider);
      this.wallets.set(chainId, wallet);
      this.tokenBridgeContracts.set(chainId, tokenBridgeContract);
      logger.info(`Switched to fallback RPC for chain ${chainId}: ${chainConfig.fallbackRpcUrl}`);
    } catch (error: any) {
      logger.error(`Failed to switch to fallback RPC for chain ${chainId}: ${error.message}`);
    }
  }

  private async handleFailedMessage(chainId: number, messageId: string) {
    try {
      const sourceTokenBridgeContract = this.tokenBridgeContracts.get(chainId);
      const sourceChainConfig = this.chainConfigs.get(chainId);
      if (!sourceTokenBridgeContract || !sourceChainConfig) {
        logger.error(`Source chain ${chainId} not initialized for message ${messageId}`);
        saveFailedMessage(chainId, messageId);
        return;
      }

      const [isFixed, isProcessed] = await Promise.all([
        sourceTokenBridgeContract.isMessageFixed(messageId),
        sourceTokenBridgeContract.isMessageProcessed(messageId)
      ]);

      if (isFixed) {
        logger.warn(`Message ${messageId} already fixed on chain ${chainId}`);
        return;
      }
      if (isProcessed) {
        logger.warn(`Message ${messageId} was processed, cannot fix on chain ${chainId}`);
        return;
      }

      let gasLimit: bigint;
      try {
        gasLimit = await sourceTokenBridgeContract.fixFailedMessage.estimateGas(messageId);
        const bufferPercent = sourceChainConfig.gasLimitBufferPercent || 20;
        gasLimit = (gasLimit * BigInt(100 + bufferPercent)) / BigInt(100);
      } catch (error: any) {
        logger.error(`Failed to estimate gas for fixFailedMessage ${messageId}: ${error.message}`);
        saveFailedMessage(chainId, messageId);
        return;
      }

      let attempts = 0;
      const initialDelay = 10000;
      while (attempts < this.maxRetries) {
        try {
          const tx: TransactionResponse = await sourceTokenBridgeContract.fixFailedMessage(messageId, { gasLimit });
          logger.info(`fixFailedMessage sent for message ${messageId}: ${tx.hash}`);
          const receipt = await tx.wait();
          if (receipt?.status === 1) {
            logger.info(`Message ${messageId} fixed on chain ${chainId}: tx=${tx.hash}`);
            return;
          }
        } catch (error: any) {
          attempts++;
          const delay = initialDelay * Math.pow(2, attempts);
          logger.warn(`Retry ${attempts}/${this.maxRetries} for fixFailedMessage ${messageId}: ${error.message}`);
          if (error.message.includes('Too Many Requests') && sourceChainConfig.fallbackRpcUrl) {
            logger.info(`Switching to fallback RPC for chain ${chainId}: ${sourceChainConfig.fallbackRpcUrl}`);
            await this.switchToFallbackRpc(chainId);
            return;
          }
          if (attempts === this.maxRetries) {
            logger.error(`Max retries reached for fixFailedMessage ${messageId}`);
            saveFailedMessage(chainId, messageId);
            return;
          }
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    } catch (error: any) {
      logger.error(`Failed to fix message ${messageId} on chain ${chainId}: ${error.message}`);
      saveFailedMessage(chainId, messageId);
    }
  }

  private async retryFailedMessages() {
    const queue = fs.existsSync(queueFile) ? JSON.parse(fs.readFileSync(queueFile, 'utf-8')) : [];
    const now = Date.now();
    const updatedQueue = [];

    for (const entry of queue) {
      if (now - entry.timestamp < this.failedMessageTtlMs) {
        await this.handleFailedMessage(entry.chainId, entry.messageId);
        if (!(await this.tokenBridgeContracts.get(entry.chainId)?.isMessageFixed(entry.messageId))) {
          updatedQueue.push(entry);
        }
      }
    }

    fs.writeFileSync(queueFile, JSON.stringify(updatedQueue));
    logger.info(`Retried failed messages, ${updatedQueue.length} remain`);
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

main().catch(error => {
  logger.error(`Main function failed: ${error.message}`, { error: JSON.stringify(error) });
  process.exit(1);
});