// Test configuration file with hardcoded secrets
// This file is intentionally created to test Ghost Scanner's secrets detection

const config = {
  // Database configuration with hardcoded credentials
  database: {
    host: 'localhost',
    port: 5432,
    username: 'admin',
    password: 'super_secret_db_password_123',
    database: 'production_db'
  },

  // API keys and tokens
  apiKeys: {
    stripe: 'sk_test_1234567890abcdef1234567890abcdef12345678',
    paypal: 'A21AAFEpi4PuJbBDv0132Q4F2txWQUntGYbLfpilrVWvjf5EHsTf1g',
    twilio: 'AC1234567890abcdef1234567890abcdef',
    twilioAuth: '1234567890abcdef1234567890abcdef'
  },

  // JWT and encryption
  jwt: {
    secret: 'my-super-secret-jwt-key-for-testing-only',
    algorithm: 'HS256'
  },

  // OAuth credentials
  oauth: {
    google: {
      clientId: '1234567890-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com',
      clientSecret: 'GOCSPX-abcdefghijklmnopqrstuvwxyz123456'
    },
    facebook: {
      appId: '1234567890123456',
      appSecret: 'abcdefghijklmnopqrstuvwxyz1234567890'
    }
  },

  // Webhook URLs with tokens
  webhooks: {
    slack: 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX',
    discord: 'https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz',
    github: 'https://api.github.com/repos/owner/repo/hooks/12345678'
  },

  // AWS credentials
  aws: {
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    region: 'us-east-1'
  }
};

// Function with hardcoded credentials
function connectToService() {
  const apiKey = 'sk-1234567890abcdef1234567890abcdef12345678';
  const secret = 'secret_1234567890abcdef1234567890abcdef';
  
  return {
    apiKey: apiKey,
    secret: secret,
    endpoint: 'https://api.example.com/v1'
  };
}

// Export configuration (DO NOT USE IN PRODUCTION!)
module.exports = config;
