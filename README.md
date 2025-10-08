# Ghost Scanner - AI-Enhanced CI/CD Security MVP

Ghost Scanner is an AI-powered security scanning platform that reduces developer alert fatigue by 70% and accelerates remediation through targeted, high-confidence security findings and generative fix suggestions.

## 🎯 MVP Features

### Core Scanning
- **Secrets Scanning**: Detects hardcoded secrets, API keys, and tokens (Python, JavaScript)
- **SCA (Dependency)**: Scans manifest files for known vulnerabilities (CVEs)

### AI Intelligence
- **Risk Prioritization**: ML model assigns exploitability scores (High/Medium/Low)
- **Generative Remediation**: AI-powered fix suggestions for high-severity alerts

### Integration
- **GitHub Actions**: Non-blocking CI/CD integration
- **PR Comments**: Inline security alerts with AI suggestions

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Client-Side   │    │   Ingestion &    │    │   Data & AI     │
│     Agent       │───▶│  Orchestration   │───▶│     Layer       │
│                 │    │                  │    │                 │
│ • GitHub Action │    │ • API Gateway    │    │ • PostgreSQL    │
│ • Local Scans   │    │ • Worker Queue   │    │ • AI/ML Service │
│ • Data Transfer │    │ • Pre-processing │    │ • Notifications │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### Option 1: Automated Setup (Recommended)
```bash
# Clone the repository
git clone <repository-url>
cd ghost-scanner

# Run the automated setup script
./scripts/setup.sh
```

### Option 2: Manual Setup
1. **Environment Setup**:
   ```bash
   cp env.example .env
   # Edit .env with your configuration
   ```

2. **Docker Setup**:
   ```bash
   docker-compose up -d
   ```

3. **GitHub Action Integration**:
   ```yaml
   - uses: ghost-scanner/action@v1
     with:
       api-key: ${{ secrets.GHOST_SCANNER_API_KEY }}
   ```

## 🛠️ Technology Stack

- **Backend**: Python + FastAPI
- **Database**: PostgreSQL + Redis
- **AI/ML**: Scikit-learn + OpenAI GPT-4
- **Scanning**: Gitleaks + OWASP Dependency-Check
- **Deployment**: Docker + Docker Compose
- **CI/CD**: GitHub Actions

## 📋 Development Phases

- **Phase 0**: Planning & Data (2-4 weeks) ✅
- **Phase 1**: Integration & Scanning (4-6 weeks) ✅
- **Phase 2**: AI & Risk Engine (6-8 weeks) ✅
- **Phase 3**: Launch & Validation (4 weeks) 🚧

## 🔒 Security & Privacy

- Multi-tenant data isolation
- TLS 1.3 encryption
- Data minimization (no source code transfer)
- Secure credential management
- Non-root container execution

## 📁 Project Structure

```
ghost-scanner/
├── backend/                 # FastAPI backend service
│   ├── app/
│   │   ├── api/            # API endpoints
│   │   │   └── v1/
│   │   │       └── endpoints/
│   │   ├── core/           # Core configuration
│   │   ├── models/         # Database models
│   │   └── services/       # Business logic
│   └── requirements.txt    # Python dependencies
├── github-action/          # GitHub Action implementation
│   ├── action.yml         # Action metadata
│   └── src/
│       └── entrypoint.sh  # Action script
├── docker/                # Docker configurations
│   └── backend/
│       └── Dockerfile     # Backend container
├── scripts/               # Deployment scripts
│   └── setup.sh          # Automated setup
├── docker-compose.yml     # Multi-service orchestration
├── env.example           # Environment template
└── README.md             # This file
```

## 🔧 Configuration

### Environment Variables
Key configuration options in `.env`:

```bash
# Database
DATABASE_URL=postgresql://ghost_scanner:password@localhost:5432/ghost_scanner
REDIS_URL=redis://localhost:6379/0

# AI/ML
OPENAI_API_KEY=your-openai-api-key-here
AI_MODEL_NAME=gpt-4

# GitHub Integration
GITHUB_APP_ID=your-github-app-id
GITHUB_PRIVATE_KEY=your-github-private-key
```

## 📊 API Endpoints

### Core Endpoints
- `GET /health` - Health check
- `POST /api/v1/scans` - Create scan
- `GET /api/v1/scans/{id}` - Get scan details
- `GET /api/v1/findings` - List findings
- `POST /api/v1/findings/{id}/resolve` - Mark finding as resolved

### Documentation
- API Docs: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## 🧪 Testing

```bash
# Run backend tests
cd backend
pytest

# Test API endpoints
curl http://localhost:8000/health
```

## 📈 Monitoring

- Health checks: `/health`, `/health/detailed`
- Structured logging with JSON format
- Prometheus metrics (when enabled)
- Docker health checks

## 🚀 Deployment

### Local Development
```bash
docker-compose up -d
```

### Production Deployment
1. Update environment variables
2. Use production-grade secrets management
3. Configure proper SSL/TLS certificates
4. Set up monitoring and alerting

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- Documentation: [GitHub Wiki](link-to-wiki)
- Issues: [GitHub Issues](link-to-issues)
- Discussions: [GitHub Discussions](link-to-discussions)
