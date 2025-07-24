# Lab 11: Using Snyk to Find & Fix Vulnerabilities
## 1. Introduction
### What is Snyk and why is it important?
Snyk is a developer-first security platform that helps identify and fix vulnerabilities in code, open-source dependencies, container images, and infrastructure as code (IaC). It enables developers to find and remediate security issues early in the development lifecycle, without slowing down the development process.

By integrating Snyk into the software development pipeline, teams can benefit from:

- **Automated vulnerability scanning** during coding, testing, and deployment.
- **Real-time feedback** on insecure dependencies or misconfigurations.
- **Fix recommendations and pull requests** that help resolve issues quickly.
- **Support for CI/CD integration**, enabling continuous security checks.
- **Detailed reporting and dashboards** for monitoring project health.

Using Snyk improves an organization’s security posture by shifting security left—addressing vulnerabilities earlier, where fixes are faster and less costly.

### Review the BlitzProp challenge: what security issues are being addressed?
The BlitzProp challenge highlights critical security vulnerabilities commonly found in JavaScript applications, specifically:

**1. Prototype Pollution**
The app improperly merges user input into objects using functions like Object.assign() without validating or sanitizing the input. This allows an attacker to manipulate the JavaScript object prototype by injecting properties via the special __proto__ key. As a result, global objects can be polluted, causing unauthorized access or behavior changes throughout the application.

**2. Vulnerable Dependencies**
BlitzProp relies on outdated versions of the flat npm package, which is susceptible to prototype pollution vulnerabilities (Snyk ID: SNYK-JS-FLAT-596927). It also uses the pug template engine with known remote code execution risks (Snyk ID: SNYK-JS-PUG-1071616).

**3. Lack of Input Validation**
User inputs are directly processed without proper sanitization, allowing exploits such as prototype pollution and template injection, which can lead to unauthorized file access or remote code execution.

Together, these issues enable attackers to bypass security controls, access sensitive data (like hidden flag files), and potentially execute arbitrary code, demonstrating the importance of secure coding practices and dependency management.

## 2. Steps Performed
### Description

In this step, I set up the Goof vulnerable application, which is an intentionally insecure Node.js app created by Snyk to demonstrate how common vulnerabilities in open-source dependencies can be found and fixed.

### Commands Used

```bash
# Clone the Goof GitHub repository
git clone https://github.com/snyk/nodejs-goof.git
# Exploration
cd goof
ls
# Install Node.js dependencies
npm install

# Start the application
docker-compose up --build
http://localhost:3001
```


