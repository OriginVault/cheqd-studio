#!/usr/bin/env node

/**
 * Environment variable checker for cheqd-studio
 * This script helps diagnose configuration issues that might cause SIGSEGV errors
 */

const requiredEnvVars = [
  'EXTERNAL_DB_ENCRYPTION_KEY',
  'MAINNET_RPC_URL',
  'TESTNET_RPC_URL'
];

console.log('🔍 Checking environment variables...\n');

let allValid = true;

for (const envVar of requiredEnvVars) {
  const value = process.env[envVar];
  
  if (!value) {
    console.log(`❌ ${envVar}: NOT SET`);
    allValid = false;
  } else if (envVar === 'EXTERNAL_DB_ENCRYPTION_KEY') {
    if (value.length < 32) {
      console.log(`❌ ${envVar}: TOO SHORT (${value.length} chars, need at least 32)`);
      allValid = false;
    } else {
      console.log(`✅ ${envVar}: SET (${value.length} chars)`);
    }
  } else {
    console.log(`✅ ${envVar}: SET`);
  }
}

console.log('\n' + '='.repeat(50));

if (allValid) {
  console.log('✅ All required environment variables are properly configured!');
  console.log('If you\'re still getting SIGSEGV errors, the issue might be:');
  console.log('1. Memory issues with the SecretBox implementation');
  console.log('2. Node.js version compatibility issues');
  console.log('3. System-level memory constraints');
} else {
  console.log('❌ Some environment variables are missing or invalid!');
  console.log('Please check your .env file or environment configuration.');
  console.log('\nRequired format for EXTERNAL_DB_ENCRYPTION_KEY:');
  console.log('- At least 32 characters long');
  console.log('- Should be a secure random string');
  console.log('- Example: "your-very-long-secure-encryption-key-here-32-chars-min"');
}

console.log('\n' + '='.repeat(50)); 