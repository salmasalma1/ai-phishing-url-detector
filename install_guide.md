# Installation Guide for Phishing Detector

## Quick Start (No ML Dependencies)

If you're having trouble with pandas/numpy installation, use the simple version:

```bash
# Install only the essential dependency
pip install tldextract

# Run the simple detector
python simple_phishing_detector.py
```

## Full Installation (With ML Features)

### Option 1: Install Dependencies One by One

```bash
# Install tldextract first (required)
pip install tldextract

# Then install ML dependencies (if needed)
pip install numpy
pip install pandas
pip install scikit-learn

# Optional: requests for advanced features
pip install requests
```

### Option 2: Use Conda (Recommended for ML)

```bash
# Install conda if you don't have it
# Then create a new environment
conda create -n phishing-detector python=3.8
conda activate phishing-detector

# Install dependencies
conda install numpy pandas scikit-learn
pip install tldextract requests
```

### Option 3: Use Older Versions

```bash
# Try older, more stable versions
pip install numpy==1.19.0
pip install pandas==1.1.0
pip install scikit-learn==0.24.0
pip install tldextract==3.1.0
```

## Troubleshooting

### Pandas Installation Error

If you get the "metadata-generation-failed" error for pandas:

1. **Use the simple version** (no ML dependencies):
   ```bash
   pip install tldextract
   python simple_phishing_detector.py
   ```

2. **Try conda instead of pip**:
   ```bash
   conda install pandas
   ```

3. **Use older versions**:
   ```bash
   pip install pandas==1.1.0
   ```

4. **Update pip and setuptools**:
   ```bash
   python -m pip install --upgrade pip setuptools wheel
   ```

### Tldextract Issues

If tldextract fails to install:

```bash
# Try with specific version
pip install tldextract==3.1.0

# Or install dependencies manually
pip install requests-file idna
```

### Python Version Issues

Make sure you have Python 3.7 or higher:

```bash
python --version
```

If not, upgrade Python or use conda:
```bash
conda install python=3.8
```

## Which Version to Use?

### Simple Phishing Detector (`simple_phishing_detector.py`)
- ✅ **No ML dependencies** - Just needs `tldextract`
- ✅ **Easy to install** - One dependency
- ✅ **Fast and lightweight**
- ✅ **Still very effective** - Rule-based detection
- ❌ **No machine learning** features

### Enhanced Phishing Detector (`enhanced_phishing_detector.py`)
- ✅ **Machine learning** capabilities
- ✅ **Higher accuracy** potential
- ✅ **Feature analysis** and insights
- ❌ **More dependencies** required
- ❌ **Complex installation**

### Basic Phishing Detector (`main.py`)
- ✅ **Middle ground** - Enhanced rules
- ✅ **Good features** without ML
- ✅ **Moderate dependencies**

## Test Installation

After installation, test with:

```bash
# Test simple version
python simple_phishing_detector.py

# Test enhanced version (if ML dependencies installed)
python enhanced_phishing_detector.py

# Test basic version
python main.py
```

## Minimum Requirements

- Python 3.7+
- tldextract (for all versions)
- Optional: numpy, pandas, scikit-learn (for ML features)

## Still Having Issues?

1. Use the **simple version** - it works with just tldextract
2. Try **conda** instead of pip for ML dependencies
3. Check your **Python version** - upgrade if needed
4. Make sure **pip is updated**: `python -m pip install --upgrade pip`

The simple version (`simple_phishing_detector.py`) provides excellent phishing detection without the complex dependencies!
