# Security Policy

## Overview

AegisShield is a security-focused application that helps organizations identify and assess cybersecurity threats. We take the security of this project seriously and appreciate efforts to responsibly disclose security vulnerabilities.

## Supported Versions

We currently support the following versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in AegisShield, please report it by:

1. **DO NOT** open a public GitHub issue
2. Email the maintainers directly with details including:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if applicable)

### What to Expect

- **Acknowledgment**: Within 48 hours of your report
- **Initial Assessment**: Within 5 business days
- **Resolution Timeline**: Critical vulnerabilities will be prioritized for immediate patching
- **Credit**: Security researchers will be credited (unless anonymity is requested)

## Security Considerations for Users

### API Key Management

**CRITICAL**: Never commit API keys to version control

- Store API keys in environment variables or `local_config.py` (which is gitignored)
- Rotate API keys regularly
- Use separate API keys for development and production
- Immediately revoke any exposed API keys

Required API keys:
- OpenAI API Key (for threat analysis)
- NVD API Key (for vulnerability data)
- AlienVault OTX API Key (for threat intelligence)

### Configuration Security

Create `local_config.py` for local development:

```python
default_nvd_api_key = "YOUR_NVD_KEY"
default_openai_api_key = "YOUR_OPENAI_KEY"
default_alienvault_api_key = "YOUR_ALIENVAULT_KEY"
```

**Never commit this file** - it's included in `.gitignore`

### Docker Security

When running AegisShield in Docker:

```bash
# Use environment variables instead of hardcoding keys
docker run -p 8501:8501 \
  -e OPENAI_API_KEY=${OPENAI_API_KEY} \
  -e NVD_API_KEY=${NVD_API_KEY} \
  -e ALIENVAULT_API_KEY=${ALIENVAULT_API_KEY} \
  aegisshield
```

- Run containers as non-root user when possible
- Use Docker secrets for production deployments
- Regularly update base images for security patches
- Scan images for vulnerabilities before deployment

### Input Validation

AegisShield processes user-provided application descriptions and architecture diagrams:

- All user inputs are sanitized before processing
- File uploads are validated for type and size
- Generated content is escaped to prevent injection attacks
- AI-generated content is validated before display

### Network Security

- Use HTTPS when deploying in production environments
- Configure proper CORS policies
- Implement rate limiting for API endpoints
- Use secure communication channels for threat intelligence APIs

## Security Features

### Built-in Security Measures

1. **Centralized Error Handling**: Comprehensive error handling prevents information leakage
2. **API Key Validation**: Validates presence and format of API keys before requests
3. **Input Sanitization**: All user inputs are sanitized before AI processing
4. **Session Management**: Secure Streamlit session state management
5. **Data Validation**: Strict validation of API responses and data structures

### Secure Development Practices

- Dependencies are pinned to specific versions in `requirements.txt`
- Regular dependency updates and security scanning
- Code quality checks with Ruff and Pylint
- Comprehensive test coverage with pytest
- Error logging without exposing sensitive information

## Known Security Limitations

1. **Client-Side Processing**: As a Streamlit application, some processing occurs client-side
2. **API Dependencies**: Security depends on third-party API providers (OpenAI, NVD, OTX)
3. **AI-Generated Content**: AI-generated threat models should be validated by security professionals
4. **Local Execution**: Currently designed for local/trusted environments, not public internet exposure

## Deployment Security Recommendations

### Development Environment

- Use virtual environments to isolate dependencies
- Never use production API keys in development
- Enable debug logging for troubleshooting only
- Restrict access to development instances

### Production Environment

- Deploy behind authentication/authorization layer
- Use environment-specific API keys with minimal permissions
- Implement logging and monitoring
- Regular security audits of generated threat models
- Backup sensitive configuration separately
- Use secret management solutions (e.g., AWS Secrets Manager, HashiCorp Vault)

### Network Configuration

- Deploy in private networks or behind VPN
- Use reverse proxy with SSL/TLS termination
- Implement IP whitelisting if applicable
- Configure firewall rules appropriately

## Dependency Security

### Regular Updates

Run security audits regularly:

```bash
# Check for known vulnerabilities
pip install safety
safety check -r requirements.txt

# Update dependencies (test thoroughly)
pip list --outdated
```

### Key Dependencies

Monitor security advisories for:
- Streamlit (web framework)
- OpenAI (AI integration)
- Requests (HTTP client)
- Pillow (image processing)
- ReportLab (PDF generation)
- Python standard library

## Compliance Considerations

### Data Privacy

- Application descriptions may contain sensitive business information
- Implement data retention policies
- Ensure compliance with data protection regulations (GDPR, CCPA, etc.)
- Consider data residency requirements for cloud deployments

### Audit Trail

- Log all threat model generation activities
- Track API usage and access patterns
- Maintain records of vulnerability assessments
- Document security incidents and responses

## Security Resources

### External References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds)
- [Streamlit Security Guidelines](https://docs.streamlit.io/)

### Security Testing

Before deploying:

1. Run full test suite: `pytest --cov=. --cov-report=html`
2. Perform static code analysis: `ruff check .`
3. Review all API key management code
4. Validate input sanitization
5. Test error handling for edge cases

## Contact

For security concerns that don't constitute vulnerabilities, please open a discussion on GitHub or contact the maintainers through appropriate channels.

---

**Last Updated**: 2025-11-17

**Note**: This security policy is subject to updates as the project evolves. Check back regularly for changes.
