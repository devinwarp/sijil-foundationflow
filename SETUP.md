# Sijill Development Setup

*Complete this setup before September 25th to be ready for development.*

## Prerequisites Check

- [ ] macOS system (confirmed)
- [ ] Python 3.11 installed
- [ ] LMStudio installed
- [ ] Git available

## 1. Python Environment Setup

### Install Python 3.11 (if not already installed)

```bash
# Check current Python version
python3 --version

# If not 3.11, install via Homebrew
brew install python@3.11
```

### Create Virtual Environment

```bash
cd /Users/shameerthaha/GitHub/hackathons/sijil-foundationflow
python3.11 -m venv venv
source venv/bin/activate
```

### Install Python Dependencies

```bash
pip install --upgrade pip
pip install fastapi httpx pyyaml cryptography reportlab uvicorn pytest pytest-asyncio
```

## 2. LMStudio Setup

### Recommended Model

**Download: Llama-3.2-3B-Instruct**

This model is ideal because:
- Small size (~2GB) - fast for local inference
- Good instruction following capabilities
- Quick response times for demo scenarios
- Widely tested and reliable

### LMStudio Configuration

1. Open LMStudio
2. Go to the Models tab
3. Search for "Llama-3.2-3B-Instruct" 
4. Download the model
5. Once downloaded, load the model
6. Enable the local server:
   - Click the server icon (usually top-right)
   - Set port to `1234` (default)
   - Enable "CORS" if available
   - Note the API token from LM Studio settings (if authentication is enabled)
   - Start the server

### Verify LMStudio API

```bash
# Set the API token (get this from LM Studio settings)
export LM_API_TOKEN=your-token-here

# Test the API is running
curl -H "Authorization: Bearer $LM_API_TOKEN" http://localhost:1234/v1/models

# Should return a JSON response with available models
```

## 3. Repository Structure Setup

Create the basic directory structure as per the spec:

```bash
cd /Users/shameerthaha/GitHub/hackathons/sijil-foundationflow

# Create directory structure
mkdir -p sijill/sijill
mkdir -p verifier
mkdir -p report
mkdir -p dashboard
mkdir -p scripts
mkdir -p tests

# Create placeholder files
touch sijill/sijill/__init__.py
touch sijill/sijill/record.py
touch sijill/sijill/store.py
touch sijill/sijill/policy.py
touch sijill/sijill/proxy.py
touch sijill/sijill/keys.py
touch verifier/sijill_verify.py
touch report/generate.py
touch report/template.html
touch dashboard/index.html
touch scripts/seed.py
touch scripts/bench.py
touch scripts/tamper.sh
touch tests/__init__.py
touch policy.yaml
```

## 4. Initial Policy File

Create the initial `policy.yaml`:

```yaml
policy_id: gov-assistant
version_label: "2026-09-25.1"
approval_ref: "APR-0147"
node:
  id: "auh-node-01"
  region: "AE-AZ"
rules:
  - id: residency
    type: region_allowlist
    allow: ["AE-AZ", "AE-DU"]
    mode: enforce
  - id: approved_models
    type: model_allowlist
    allow_digests: ["<digest of the pulled model>"]
    mode: enforce
  - id: sensitive_terms
    type: keyword_flag
    terms: ["emirates id", "passport number"]
    mode: record
```

## 5. Verification Steps

### Verify Python Setup

```bash
cd /Users/shameerthaha/GitHub/hackathons/sijil-foundationflow
source venv/bin/activate
python --version  # Should show Python 3.11.x
pip list  # Should show installed packages
```

### Verify LMStudio

```bash
curl -H "Authorization: Bearer $LM_API_TOKEN" http://localhost:1234/v1/models
```

Expected response: JSON with model information

### Verify Directory Structure

```bash
ls -la sijill/sijill/
ls -la verifier/
ls -la report/
ls -la dashboard/
ls -la scripts/
ls -la tests/
```

## 6. Development Environment Configuration

### Environment Variables (Optional)

Create a `.env` file for development:

```bash
# LMStudio endpoint
LMSTUDIO_BASE_URL=http://localhost:1234/v1

# LMStudio API token (if authentication is enabled)
LM_API_TOKEN=your-token-here

# Database path
DATABASE_PATH=sijill.db

# Policy file path
POLICY_PATH=policy.yaml
```

### Git Setup

```bash
# Initialize git if not already done
git init

# Create .gitignore
cat > .gitignore << 'EOF'
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
venv/
env/
ENV/
.venv
sijill.db
*.db
.env
.env.local
.env.*.local
.DS_Store
EOF
```

## 7. Pre-Development Verification

Run this final check to ensure everything is ready:

```bash
#!/bin/bash
echo "=== Sijill Development Setup Verification ==="

# Check Python
echo "Checking Python version..."
python --version

# Check virtual environment
echo "Checking virtual environment..."
if [ -d "venv" ]; then
    echo "✓ Virtual environment exists"
else
    echo "✗ Virtual environment missing"
fi

# Check dependencies
echo "Checking key dependencies..."
python -c "import fastapi; print('✓ FastAPI installed')"
python -c "import httpx; print('✓ httpx installed')"
python -c "import yaml; print('✓ PyYAML installed')"
python -c "from cryptography.hazmat.primitives.asymmetric import ed25519; print('✓ cryptography installed')"
python -c "import reportlab; print('✓ reportlab installed')"

# Check LMStudio
echo "Checking LMStudio API..."
if [ -n "$LM_API_TOKEN" ]; then
    if curl -s -H "Authorization: Bearer $LM_API_TOKEN" http://localhost:1234/v1/models > /dev/null 2>&1; then
        echo "✓ LMStudio API is accessible (with authentication)"
    else
        echo "✗ LMStudio API not accessible - check token and server"
    fi
else
    if curl -s http://localhost:1234/v1/models > /dev/null 2>&1; then
        echo "✓ LMStudio API is accessible (no authentication)"
    else
        echo "✗ LMStudio API not accessible - ensure LMStudio server is running"
    fi
fi

# Check directory structure
echo "Checking directory structure..."
for dir in sijill/sijill verifier report dashboard scripts tests; do
    if [ -d "$dir" ]; then
        echo "✓ $dir exists"
    else
        echo "✗ $dir missing"
    fi
done

echo "=== Setup Verification Complete ==="
```

## 8. Ready for Development on September 25th

Once all checks pass, you're ready to start development. The first task will be:

> Build the verifier CLI in `verifier/sijill_verify.py` exactly as specified under "Canonicalisation and hashing" and "Verifier CLI". Do not import anything from the `sijill/` package.

## Troubleshooting

### LMStudio Connection Issues
- Ensure LMStudio server is started (look for the server icon)
- Check that port 1234 is not blocked by firewall
- If you get authentication errors, set the LM_API_TOKEN environment variable
- Get your API token from LM Studio settings
- Try accessing `http://localhost:1234` in browser

### Python Package Issues
- Ensure you're using the virtual environment: `source venv/bin/activate`
- Try upgrading pip: `pip install --upgrade pip`
- Install packages individually if batch install fails

### Permission Issues
- If you get permission errors, try with `--user` flag: `pip install --user <package>`
- Or use sudo (not recommended for virtual environments)

## Notes

- This setup should take approximately 30-45 minutes
- All dependencies are standard Python packages
- No cloud services or external APIs required
- Everything runs locally on your machine
- The demo is designed to work offline once LMStudio model is downloaded
