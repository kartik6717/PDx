# PDF Scrubber Deployment Guide

## Production Deployment Overview

This guide covers the complete deployment process for the PDF Scrubber system, from build to production deployment with security, monitoring, and maintenance considerations.

## Prerequisites

### System Requirements

#### Minimum Requirements
- **OS**: Linux (Ubuntu 20.04+, CentOS 8+, RHEL 8+)
- **Memory**: 2GB RAM
- **Storage**: 10GB available space
- **CPU**: 2 cores, x86_64 architecture

#### Recommended Requirements
- **Memory**: 8GB RAM
- **Storage**: 50GB available space
- **CPU**: 4+ cores, x86_64 architecture
- **Network**: Reliable internet connection for updates

#### Dependencies
- **C++ Compiler**: GCC 9+ or Clang 10+
- **CMake**: Version 3.16+
- **OpenSSL**: Version 1.1.1+ or 3.0+
- **zlib**: Version 1.2.11+
- **pkg-config**: For dependency detection

## Quick Start Deployment

### 1. Automated Deployment (Recommended)

```bash
# Clone repository
git clone https://github.com/pdfscrubber/pdfscrubber.git
cd pdfscrubber

# Make scripts executable
chmod +x build.sh deploy.sh

# Build and deploy
./build.sh
sudo ./deploy.sh deploy
```

### 2. Manual Deployment

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config libssl-dev zlib1g-dev

# Build project
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Install
sudo make install
```

## Docker Deployment

### Production Container

```bash
# Build image
docker build -t pdfscrubber:latest .

# Run container
docker run -d \
  --name pdfscrubber \
  --restart unless-stopped \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/config:/app/config \
  pdfscrubber:latest
```

### Docker Compose (Recommended)

```bash
# Start services
docker-compose up -d

# Development mode
docker-compose --profile development up -d

# Testing
docker-compose --profile testing up
```

## Build System Details

### CMake Configuration Options

```bash
# Debug build
cmake -DCMAKE_BUILD_TYPE=Debug ..

# Release with custom prefix
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/pdfscrubber ..

# Cross-compilation
cmake -DCMAKE_TOOLCHAIN_FILE=toolchain.cmake ..
```

### Build Targets

- `pdfscrubber` - Main scrubbing application
- `pdfforensic` - Forensic analysis tool
- `test_suite` - Comprehensive test runner
- `build_test` - Quick build verification

### Testing

```bash
# Run all tests
cd build && ctest

# Run specific test
./test_suite --test-case="PDF Parser"

# Run benchmarks
./test_suite --benchmark
```

## Production Configuration

### Service Configuration

The deployment creates a systemd service with the following features:

- **Security**: Sandboxed execution with restricted privileges
- **Monitoring**: Health checks and automatic restart
- **Logging**: Structured logging with rotation
- **Resource Limits**: Memory and CPU limits

#### Service Management

```bash
# Service status
sudo systemctl status pdfscrubber

# Start/stop/restart
sudo systemctl start pdfscrubber
sudo systemctl stop pdfscrubber
sudo systemctl restart pdfscrubber

# View logs
sudo journalctl -u pdfscrubber -f
```

### Configuration Files

#### Main Configuration (`/opt/pdfscrubber/config/scrubber.conf`)

```ini
[scrubber]
max_file_size = 100MB
max_objects = 100000
strict_validation = true
enable_recovery = true

[logging]
level = info
file = /opt/pdfscrubber/logs/scrubber/scrubber.log

[security]
enable_sandbox = true
memory_limit = 2GB
```

#### Environment-Specific Configurations

- **Development**: Verbose logging, relaxed limits
- **Staging**: Production-like with debug features
- **Production**: Optimized for performance and security

## Security Considerations

### System Security

1. **User Isolation**: Runs under dedicated `pdfscrubber` user
2. **File Permissions**: Restricted file system access
3. **Network**: No network access required for operation
4. **Sandboxing**: systemd security features enabled

### Application Security

1. **Input Validation**: Comprehensive PDF validation
2. **Memory Safety**: Bounds checking and memory limits
3. **DoS Protection**: Timeouts and resource limits
4. **Error Handling**: Graceful degradation

### Security Checklist

- [ ] Dedicated user account created
- [ ] File permissions properly set
- [ ] Security limits configured
- [ ] Logging enabled
- [ ] Regular updates scheduled
- [ ] Backup strategy in place

## Monitoring and Maintenance

### Health Monitoring

```bash
# Check service health
curl -f http://localhost:8080/health || echo "Service unhealthy"

# Monitor resource usage
systemctl show pdfscrubber --property=MemoryUsage
systemctl show pdfscrubber --property=CPUUsage
```

### Log Management

Logs are automatically rotated using logrotate:

- **Location**: `/opt/pdfscrubber/logs/`
- **Rotation**: Daily, 30-day retention
- **Compression**: Automatic compression of old logs

### Backup Strategy

#### Automated Backups

```bash
# Create backup
sudo -u pdfscrubber /opt/pdfscrubber/backup.sh

# Restore from backup
sudo -u pdfscrubber /opt/pdfscrubber/restore.sh backup-20231215-143000
```

#### What to Backup

- Configuration files
- Binary executables
- Custom profiles
- Application data (if any)

### Updates and Maintenance

#### Security Updates

```bash
# Update system packages
sudo apt-get update && sudo apt-get upgrade

# Update PDF Scrubber
cd /opt/pdfscrubber/source
git pull origin main
./build.sh
sudo ./deploy.sh deploy
```

#### Scheduled Maintenance

Create cron jobs for:

- Daily log cleanup
- Weekly security updates
- Monthly backup verification
- Quarterly dependency updates

## Troubleshooting

### Common Issues

#### Build Failures

```bash
# Check dependencies
pkg-config --list-all | grep -E "openssl|zlib"

# Verify compiler
g++ --version
cmake --version

# Clean build
rm -rf build && mkdir build
```

#### Runtime Issues

```bash
# Check service status
sudo systemctl status pdfscrubber

# View detailed logs
sudo journalctl -u pdfscrubber -n 100

# Test binary directly
sudo -u pdfscrubber /opt/pdfscrubber/bin/pdfscrubber --version
```

#### Permission Issues

```bash
# Fix ownership
sudo chown -R pdfscrubber:pdfscrubber /opt/pdfscrubber

# Check permissions
ls -la /opt/pdfscrubber/
```

### Debug Mode

Enable debug mode for troubleshooting:

```bash
# Stop service
sudo systemctl stop pdfscrubber

# Run in debug mode
sudo -u pdfscrubber /opt/pdfscrubber/bin/pdfscrubber --debug --console
```

## Performance Optimization

### System Optimization

1. **Memory**: Ensure adequate RAM for large files
2. **Storage**: Use SSD for better I/O performance
3. **CPU**: Multi-core systems benefit from parallel processing

### Application Tuning

```ini
[performance]
enable_caching = true
cache_size = 512MB
parallel_processing = true
max_threads = 8
```

### Monitoring Performance

```bash
# CPU usage
top -p $(pgrep pdfscrubber)

# Memory usage
ps aux | grep pdfscrubber

# I/O statistics
iotop -p $(pgrep pdfscrubber)
```

## Rollback Procedures

### Automatic Rollback

```bash
# Rollback to previous version
sudo ./deploy.sh rollback
```

### Manual Rollback

1. Stop the service
2. Restore binaries from backup
3. Restore configuration from backup
4. Start the service
5. Verify functionality

## Support and Documentation

### Additional Resources

- **API Documentation**: `/opt/pdfscrubber/docs/api/`
- **Configuration Reference**: `/opt/pdfscrubber/docs/config/`
- **Security Guidelines**: `SECURITY_CONSIDERATIONS.md`
- **Performance Guide**: `PERFORMANCE_GUIDE.md`

### Getting Help

1. Check logs first
2. Review troubleshooting section
3. Consult documentation
4. Contact support with:
   - System information
   - Error messages
   - Log excerpts
   - Configuration details

## Environment Variables

### Build Environment

- `BUILD_TYPE`: Debug or Release
- `CMAKE_INSTALL_PREFIX`: Installation directory
- `NUM_CORES`: Build parallelism

### Runtime Environment

- `PDFSCRUBBER_CONFIG`: Configuration file path
- `PDFSCRUBBER_LOG_LEVEL`: Logging level override
- `PDFSCRUBBER_DATA_DIR`: Data directory override