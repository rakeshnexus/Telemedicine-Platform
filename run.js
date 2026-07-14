const { spawn, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT_DIR = __dirname;
const CLIENT_DIR = path.join(ROOT_DIR, 'client');

// ANSI color escape sequences
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  green: '\x1b[32m',
  blue: '\x1b[34m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m'
};

function log(prefix, message, color = colors.reset) {
  const lines = message.split('\n');
  lines.forEach(line => {
    if (line.trim() !== '') {
      console.log(`${color}${prefix}${colors.reset} ${line}`);
    }
  });
}

function verifyDependencies() {
  console.log(`${colors.bright}${colors.cyan}[Runner] Verifying node_modules...${colors.reset}`);
  
  // Check root dependencies
  const rootNodeModules = path.join(ROOT_DIR, 'node_modules');
  if (!fs.existsSync(rootNodeModules)) {
    console.log(`${colors.yellow}[Runner] Root node_modules not found. Installing...${colors.reset}`);
    try {
      execSync('npm install', { cwd: ROOT_DIR, stdio: 'inherit' });
      console.log(`${colors.green}[Runner] Root dependencies installed successfully.${colors.reset}`);
    } catch (err) {
      console.error(`${colors.red}[Runner] Failed to install root dependencies:${colors.reset}`, err.message);
      process.exit(1);
    }
  } else {
    console.log(`${colors.green}[Runner] Root node_modules verified.${colors.reset}`);
  }

  // Check client dependencies
  const clientNodeModules = path.join(CLIENT_DIR, 'node_modules');
  if (!fs.existsSync(clientNodeModules)) {
    console.log(`${colors.yellow}[Runner] Client node_modules not found. Installing...${colors.reset}`);
    try {
      execSync('npm install', { cwd: CLIENT_DIR, stdio: 'inherit' });
      console.log(`${colors.green}[Runner] Client dependencies installed successfully.${colors.reset}`);
    } catch (err) {
      console.error(`${colors.red}[Runner] Failed to install client dependencies:${colors.reset}`, err.message);
      process.exit(1);
    }
  } else {
    console.log(`${colors.green}[Runner] Client node_modules verified.${colors.reset}`);
  }
}

function run() {
  verifyDependencies();

  console.log(`\n${colors.bright}${colors.cyan}[Runner] Launching servers...${colors.reset}\n`);

  // Detect shell command format depending on the platform
  const isWin = process.platform === 'win32';
  const npmCmd = isWin ? 'npm.cmd' : 'npm';

  // 1. Start backend server (nodemon server.js via npm run dev)
  const serverProcess = spawn(npmCmd, ['run', 'dev'], {
    cwd: ROOT_DIR,
    shell: true,
    env: { ...process.env, FORCE_COLOR: true }
  });

  // 2. Start client Vite server (vite via npm run dev inside client/)
  const clientProcess = spawn(npmCmd, ['run', 'dev'], {
    cwd: CLIENT_DIR,
    shell: true,
    env: { ...process.env, FORCE_COLOR: true }
  });

  // Pipe server logs
  serverProcess.stdout.on('data', (data) => {
    log('[Backend]', data.toString(), colors.green);
  });
  serverProcess.stderr.on('data', (data) => {
    log('[Backend-Err]', data.toString(), colors.red);
  });

  // Pipe client logs
  clientProcess.stdout.on('data', (data) => {
    log('[Client]', data.toString(), colors.blue);
  });
  clientProcess.stderr.on('data', (data) => {
    log('[Client-Err]', data.toString(), colors.red);
  });

  // Clean termination handler
  const shutdown = () => {
    console.log(`\n${colors.bright}${colors.yellow}[Runner] Shutting down subprocesses...${colors.reset}`);
    
    let serverKilled = false;
    let clientKilled = false;

    if (serverProcess) {
      console.log(`${colors.cyan}[Runner] Stopping backend server...${colors.reset}`);
      if (isWin) {
        // Windows process tree kill to ensure nodemon and node child processes are terminated
        try {
          execSync(`taskkill /pid ${serverProcess.pid} /t /f`, { stdio: 'ignore' });
        } catch (e) {
          serverProcess.kill('SIGINT');
        }
      } else {
        serverProcess.kill('SIGINT');
      }
      serverKilled = true;
    }

    if (clientProcess) {
      console.log(`${colors.cyan}[Runner] Stopping client server...${colors.reset}`);
      if (isWin) {
        try {
          execSync(`taskkill /pid ${clientProcess.pid} /t /f`, { stdio: 'ignore' });
        } catch (e) {
          clientProcess.kill('SIGINT');
        }
      } else {
        clientProcess.kill('SIGINT');
      }
      clientKilled = true;
    }

    console.log(`${colors.green}[Runner] Shutdown complete.${colors.reset}`);
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  serverProcess.on('close', (code) => {
    console.log(`${colors.red}[Runner] Backend server exited with code ${code}.${colors.reset}`);
    shutdown();
  });

  clientProcess.on('close', (code) => {
    console.log(`${colors.red}[Runner] Client server exited with code ${code}.${colors.reset}`);
    shutdown();
  });
}

run();
