"""
directory_scanner.py — Checks for exposure of sensitive files and directories.
Tests a curated list of paths commonly left exposed on misconfigured web servers.
No external dependencies required.
"""
from scanners.base_scanner import BaseScanner

SENSITIVE_PATHS = [
    # Source Control
    ("/.git/config",            "Git Config Exposed",              "Critical", 9.8,
     "The .git/config file reveals remote repository URLs, branches, and potentially credentials. Attackers can clone the entire source code.",
     "Block .git access in web server:\n  Nginx: location ~ /\\.git { deny all; return 404; }\n  Apache: RedirectMatch 404 /\\.git"),

    ("/.git/HEAD",              "Git Repository Accessible",       "Critical", 9.1,
     "The .git directory is publicly accessible, allowing full source code reconstruction via git-dumper.",
     "Block all access to the .git directory. Never deploy web apps with .git directories in the web root."),

    ("/.svn/entries",           "SVN Repository Exposed",          "High",     7.5,
     "Subversion metadata is publicly accessible, potentially exposing source code and history.",
     "Block .svn directory access at the web server level and remove .svn directories from your web root."),

    ("/.hg/",                   "Mercurial Repository Exposed",     "High",     7.5,
     "Mercurial (Hg) repository directory is accessible, exposing version control data.",
     "Block .hg directory access and remove from web root."),

    # Environment & Config
    ("/.env",                   ".env File Exposed",               "Critical", 9.8,
     "The .env configuration file is publicly accessible. It typically contains database passwords, API keys, JWT secrets, and AWS credentials.",
     "Never place .env files in the web root. Block with:\n  Nginx: location ~ /\\.env { deny all; }"),

    ("/.env.local",             ".env.local File Exposed",         "Critical", 9.8,
     "Local environment override file is accessible, potentially containing developer credentials.",
     "Remove all .env variants from the web root and block access via server config."),

    ("/.env.backup",            ".env Backup Exposed",             "Critical", 9.8,
     "A backup of the environment configuration file is accessible.",
     "Remove all .env backup files and block access at the web server level."),

    ("/.env.production",        ".env.production File Exposed",    "Critical", 9.8,
     "Production environment configuration is publicly accessible.",
     "Remove production environment files from web root immediately."),

    ("/.env.development",       ".env.development File Exposed",  "High",     7.5,
     "Development environment configuration is accessible, potentially containing development credentials.",
     "Remove development environment files from production deployments."),

    ("/.env.staging",           ".env.staging File Exposed",       "High",     7.5,
     "Staging environment configuration is accessible.",
     "Remove staging environment files from public access."),

    ("/config.php",             "PHP Config File Exposed",         "High",     7.5,
     "A PHP configuration file containing database credentials may be readable.",
     "Move config files above the web root or restrict access."),

    ("/wp-config.php",          "WordPress Config Exposed",        "Critical", 9.8,
     "WordPress configuration file is accessible, exposing database host, name, user, and password.",
     "Ensure wp-config.php is not web-accessible. WordPress should normally protect this."),

    ("/wp-config.php.bak",      "WordPress Config Backup Exposed", "Critical", 9.8,
     "WordPress configuration backup file is accessible.",
     "Remove all .bak files from web root immediately."),

    ("/config/database.yml",    "Rails DB Config Exposed",         "Critical", 9.8,
     "Ruby on Rails database configuration file is publicly accessible with database credentials.",
     "Add config/database.yml to .gitignore and restrict web access."),

    ("/appsettings.json",       "ASP.NET Config Exposed",          "High",     7.5,
     "ASP.NET Core configuration file may expose connection strings and API keys.",
     "Restrict web access to appsettings.json. Use Azure Key Vault or environment variables for secrets."),

    ("/application.properties","Java Config Exposed",             "High",     7.5,
     "Java/Spring application properties file may contain database credentials and API keys.",
     "Move configuration files outside web root or use environment variables."),

    ("/application.yml",        "YAML Config Exposed",             "High",     7.5,
     "YAML configuration file may contain sensitive configuration data.",
     "Restrict access to configuration files."),

    ("/settings.py",            "Python Config Exposed",           "High",     7.5,
     "Python Django settings file may contain secret keys and database credentials.",
     "Move settings.py outside web root or use environment variables."),

    ("/.htaccess",              ".htaccess File Exposed",           "Medium",   5.3,
     "Apache .htaccess configuration file is readable, potentially revealing rewrite rules and security configurations.",
     "Restrict access to .htaccess files."),

    ("/.htpasswd",              ".htpasswd File Exposed",           "High",     7.5,
     "Apache .htpasswd file contains password hashes for basic authentication.",
     "Remove .htpasswd files from web root immediately."),

    # Admin Panels
    ("/admin",                  "Admin Panel Exposed",             "Medium",   5.3,
     "An admin panel is publicly accessible. Exposed admin interfaces are prime targets for brute-force and credential stuffing attacks.",
     "Restrict admin access to specific IP ranges:\n  Nginx: allow 10.0.0.0/8; deny all;"),

    ("/administrator",          "Admin Panel Exposed",             "Medium",   5.3,
     "Administrator panel is publicly accessible.",
     "Restrict access and implement strong authentication."),

    ("/wp-admin/",              "WordPress Admin Exposed",         "Medium",   5.3,
     "WordPress admin login is publicly accessible, enabling brute-force attacks.",
     "Use plugins like WP Cerber or Wordfence to limit login attempts. Consider hiding wp-admin via URL change."),

    ("/wp-login.php",           "WordPress Login Exposed",         "Medium",   5.3,
     "WordPress login page is publicly accessible.",
     "Implement rate limiting and 2FA for WordPress logins."),

    ("/phpmyadmin/",            "phpMyAdmin Exposed",              "High",     8.0,
     "phpMyAdmin database management interface is publicly accessible. Default credentials are widely known.",
     "Remove phpMyAdmin from public-facing servers. Access databases only via SSH tunnel."),

    ("/adminer.php",            "Adminer DB Manager Exposed",      "High",     8.0,
     "Adminer database management tool is publicly accessible on the production server.",
     "Remove adminer.php from production. Use SSH tunnels for database management."),

    ("/mysql/",                 "MySQL Admin Exposed",             "High",     8.0,
     "MySQL administration interface is publicly accessible.",
     "Remove MySQL admin interfaces from public access."),

    ("/pgadmin/",               "pgAdmin Exposed",                "High",     8.0,
     "PostgreSQL administration interface is publicly accessible.",
     "Remove pgAdmin from public access."),

    ("/solr/",                  "Apache Solr Exposed",             "Medium",   5.3,
     "Apache Solr search interface is publicly accessible.",
     "Restrict access to Solr admin interface."),

    ("/elasticsearch/",         "Elasticsearch Exposed",           "Medium",   5.3,
     "Elasticsearch interface is publicly accessible.",
     "Restrict access to Elasticsearch."),

    ("/kibana/",                "Kibana Exposed",                 "Medium",   5.3,
     "Kibana dashboard is publicly accessible.",
     "Restrict access to Kibana."),

    ("/grafana/",               "Grafana Exposed",                "Medium",   5.3,
     "Grafana dashboard is publicly accessible.",
     "Restrict access to Grafana."),

    ("/jenkins/",               "Jenkins Exposed",                "Medium",   5.3,
     "Jenkins CI/CD server is publicly accessible.",
     "Restrict access to Jenkins."),

    ("/jira/",                  "Jira Exposed",                   "Medium",   5.3,
     "Jira issue tracker is publicly accessible.",
     "Restrict access to Jira."),

    ("/confluence/",            "Confluence Exposed",             "Medium",   5.3,
     "Confluence wiki is publicly accessible.",
     "Restrict access to Confluence."),

    # Backup Files
    ("/backup.zip",             "Backup Archive Exposed",          "Critical", 9.1,
     "A backup archive file is publicly downloadable. Backup files often contain full source code, databases, and configuration.",
     "Remove all backup files from the web root. Store backups in secure, non-public locations."),

    ("/backup.sql",             "SQL Backup Exposed",              "Critical", 9.8,
     "A SQL database dump is publicly downloadable, exposing all database contents.",
     "Remove SQL dumps from the web root immediately. Store in encrypted, access-controlled storage."),

    ("/db.sql",                 "SQL Database Dump Exposed",       "Critical", 9.8,
     "A SQL database dump file is publicly accessible.",
     "Delete immediately and audit what data was exposed. Report to your data protection authority if personal data is involved."),

    ("/backup.tar.gz",          "Tar Backup Exposed",              "Critical", 9.1,
     "A tar.gz backup archive is publicly downloadable.",
     "Remove all backup archives from web root."),

    ("/backup.bak",             "Backup File Exposed",             "Critical", 9.1,
     "A backup file is publicly accessible.",
     "Remove all .bak files from web root."),

    ("/database.sql",           "Database Dump Exposed",           "Critical", 9.8,
     "Database dump file is publicly accessible.",
     "Remove immediately and audit data exposure."),

    ("/dump.sql",               "Database Dump Exposed",           "Critical", 9.8,
     "Database dump file is publicly accessible.",
     "Remove immediately."),

    ("/.backup",                "Backup Directory Exposed",        "Critical", 9.1,
     "A backup directory is publicly accessible.",
     "Remove backup directories from web root."),

    ("/backups/",               "Backups Directory Exposed",       "Critical", 9.1,
     "Backups directory is publicly accessible.",
     "Remove backups directory from web root."),

    # Debug & Logs
    ("/server.log",             "Server Log File Exposed",         "Medium",   5.3,
     "A server log file is publicly readable, potentially revealing internal paths, errors, user data, and stack traces.",
     "Ensure log files are stored outside the web root or protected by authentication."),

    ("/error.log",              "Error Log Exposed",               "Medium",   5.3,
     "The application error log is publicly accessible, revealing internal application errors and stack traces.",
     "Move log files outside the web root and ensure they are never publicly accessible."),

    ("/access.log",             "Access Log Exposed",              "Medium",   5.3,
     "Access log file is publicly readable, potentially revealing user activity and internal paths.",
     "Move access logs outside web root."),

    ("/debug.log",              "Debug Log Exposed",               "Medium",   5.3,
     "Debug log file is publicly accessible, revealing detailed debugging information.",
     "Remove debug logs from production."),

    ("/logs/",                  "Logs Directory Exposed",           "Medium",   5.3,
     "Logs directory is publicly accessible.",
     "Move logs directory outside web root."),

    ("/phpinfo.php",            "phpinfo() Page Exposed",          "Medium",   5.3,
     "A phpinfo() page reveals PHP configuration, extensions, environment variables, and server paths.",
     "Delete phpinfo.php pages from production environments."),

    ("/info.php",               "PHP Info Page Exposed",           "Medium",   5.3,
     "PHP info page reveals server configuration.",
     "Remove info.php from production."),

    ("/test.php",               "Test Script Exposed",             "Medium",   5.3,
     "Test script is publicly accessible, potentially revealing application internals.",
     "Remove test scripts from production."),

    ("/test/",                  "Test Directory Exposed",          "Medium",   5.3,
     "Test directory is publicly accessible.",
     "Remove test directories from production."),

    # API & Metadata
    ("/api/swagger.json",       "Swagger API Docs Exposed",        "Low",      3.1,
     "Swagger/OpenAPI documentation is publicly accessible, mapping all API endpoints and their parameters.",
     "Restrict API documentation access to authenticated users or trusted IP ranges in production."),

    ("/api/openapi.json",       "OpenAPI Docs Exposed",            "Low",      3.1,
     "OpenAPI documentation is publicly accessible.",
     "Restrict access to API documentation."),

    ("/api/docs",               "API Documentation Exposed",       "Low",      3.1,
     "API documentation is publicly accessible.",
     "Restrict access to API docs."),

    ("/api/v1/users",           "Users API Endpoint Exposed",      "Medium",   5.3,
     "A user listing API endpoint is publicly accessible without authentication.",
     "Ensure all API endpoints require proper authentication and authorisation."),

    ("/api/users",              "Users API Exposed",               "Medium",   5.3,
     "Users API endpoint is publicly accessible.",
     "Implement authentication on all user endpoints."),

    ("/graphql",               "GraphQL Endpoint Exposed",         "Low",      3.1,
     "GraphQL endpoint is publicly accessible.",
     "Implement authentication on GraphQL endpoint."),

    ("/.DS_Store",              ".DS_Store File Exposed",          "Low",      3.1,
     ".DS_Store files (macOS metadata) can reveal directory structure and file names on the server.",
     "Add .DS_Store to .gitignore and block access:\n  Nginx: location ~ /\\.DS_Store { deny all; }"),

    ("/Thumbs.db",              "Thumbs.db Exposed",               "Low",      3.1,
     "Windows thumbnail database file reveals file structure.",
     "Block access to Thumbs.db files."),

    # Cloud & CI/CD
    ("/.aws/",                  "AWS Config Directory Exposed",     "Critical", 9.8,
     "AWS configuration directory is accessible, potentially containing credentials.",
     "Remove .aws directory from web root."),

    ("/.aws/credentials",       "AWS Credentials Exposed",        "Critical", 9.8,
     "AWS credentials file is publicly accessible.",
     "Remove immediately and rotate all AWS credentials."),

    ("/.kube/",                 "Kubernetes Config Exposed",       "Critical", 9.8,
     "Kubernetes configuration directory is accessible.",
     "Remove .kube directory from web root."),

    ("/.github/",               "GitHub Config Exposed",           "High",     7.5,
     "GitHub configuration directory is accessible.",
     "Remove .github directory from web root."),

    ("/.gitlab-ci.yml",        "GitLab CI Config Exposed",       "Medium",   5.3,
     "GitLab CI configuration is accessible, potentially revealing CI/CD secrets.",
     "Remove CI/CD configuration files from web root."),

    ("/.travis.yml",           "Travis CI Config Exposed",        "Medium",   5.3,
     "Travis CI configuration is accessible.",
     "Remove CI configuration files from web root."),

    ("/docker-compose.yml",     "Docker Compose Exposed",          "Medium",   5.3,
     "Docker Compose configuration is accessible, potentially revealing service configuration.",
     "Remove Docker configuration files from web root."),

    ("/Dockerfile",             "Dockerfile Exposed",              "Medium",   5.3,
     "Dockerfile is publicly accessible.",
     "Remove Dockerfile from web root."),

    ("/jenkinsfile",            "Jenkinsfile Exposed",              "Medium",   5.3,
     "Jenkins CI configuration is accessible.",
     "Remove Jenkinsfile from web root."),

    # Development Tools
    ("/composer.json",          "Composer Config Exposed",         "Medium",   5.3,
     "PHP Composer configuration is accessible, revealing package dependencies.",
     "Move composer.json outside web root."),

    ("/composer.lock",          "Composer Lock Exposed",           "Low",      3.1,
     "Composer lock file is accessible.",
     "Move composer.lock outside web root."),

    ("/package.json",           "NPM Config Exposed",              "Medium",   5.3,
     "NPM package.json is accessible, revealing dependencies and scripts.",
     "Move package.json outside web root."),

    ("/package-lock.json",      "NPM Lock Exposed",               "Low",      3.1,
     "NPM lock file is accessible.",
     "Move package-lock.json outside web root."),

    ("/Gemfile",                "Ruby Gemfile Exposed",             "Medium",   5.3,
     "Ruby Gemfile is accessible, revealing dependencies.",
     "Move Gemfile outside web root."),

    ("/Gemfile.lock",           "Gemfile Lock Exposed",            "Low",      3.1,
     "Ruby Gemfile.lock is accessible.",
     "Move Gemfile.lock outside web root."),

    ("/requirements.txt",       "Python Requirements Exposed",     "Medium",   5.3,
     "Python requirements.txt is accessible, revealing dependencies.",
     "Move requirements.txt outside web root."),

    ("/Pipfile",                "Pipfile Exposed",                 "Medium",   5.3,
     "Python Pipfile is accessible.",
     "Move Pipfile outside web root."),

    ("/go.mod",                 "Go Module Exposed",                "Medium",   5.3,
     "Go module file is accessible.",
     "Move go.mod outside web root."),

    # CMS Specific
    ("/wp-content/",            "WordPress Content Exposed",       "Low",      3.1,
     "WordPress wp-content directory is accessible.",
     "Restrict access to wp-content."),

    ("/wp-includes/",           "WordPress Includes Exposed",      "Low",      3.1,
     "WordPress wp-includes directory is accessible.",
     "Restrict access to wp-includes."),

    ("/wp-content/uploads/",    "WordPress Uploads Exposed",       "Low",      3.1,
     "WordPress uploads directory is accessible.",
     "Ensure uploads directory has proper permissions."),

    ("/drupal/",                "Drupal Directory Exposed",         "Low",      3.1,
     "Drupal directory is accessible.",
     "Restrict access to Drupal directories."),

    ("/sites/default/files/",   "Drupal Files Exposed",            "Low",      3.1,
     "Drupal files directory is accessible.",
     "Restrict access to files directory."),

    ("/magento/",               "Magento Directory Exposed",        "Low",      3.1,
     "Magento directory is accessible.",
     "Restrict access to Magento directories."),

    ("/media/",                 "Media Directory Exposed",          "Low",      3.1,
     "Media directory is accessible.",
     "Ensure media directory has proper permissions."),

    ("/static/",                "Static Files Exposed",            "Low",      3.1,
     "Static files directory is accessible.",
     "Ensure static directory has proper permissions."),

    ("/public/",                "Public Directory Exposed",        "Low",      3.1,
     "Public directory is accessible.",
     "Review contents of public directory."),

    ("/tmp/",                   "Temp Directory Exposed",           "Medium",   5.3,
     "Temporary directory is accessible.",
     "Remove temp directory from web root."),

    ("/temp/",                  "Temp Directory Exposed",           "Medium",   5.3,
     "Temporary directory is accessible.",
     "Remove temp directory from web root."),

    ("/cache/",                 "Cache Directory Exposed",          "Medium",   5.3,
     "Cache directory is accessible.",
     "Restrict access to cache directory."),

    ("/storage/",               "Storage Directory Exposed",        "Medium",   5.3,
     "Storage directory is accessible.",
     "Restrict access to storage directory."),

    ("/uploads/",               "Uploads Directory Exposed",        "Medium",   5.3,
     "Uploads directory is accessible.",
     "Ensure uploads directory has proper permissions and restrictions."),

    ("/files/",                 "Files Directory Exposed",          "Medium",   5.3,
     "Files directory is accessible.",
     "Restrict access to files directory."),

    ("/install.php",            "Install Script Exposed",          "High",     7.5,
     "Installation script is publicly accessible.",
     "Remove install.php from production."),

    ("/install/",               "Install Directory Exposed",        "High",     7.5,
     "Installation directory is accessible.",
     "Remove install directory from production."),

    ("/setup.php",              "Setup Script Exposed",            "High",     7.5,
     "Setup script is publicly accessible.",
     "Remove setup.php from production."),

    ("/upgrade.php",            "Upgrade Script Exposed",          "High",     7.5,
     "Upgrade script is publicly accessible.",
     "Remove upgrade.php from production."),

    ("/maintenance.php",        "Maintenance Script Exposed",     "Medium",   5.3,
     "Maintenance script is publicly accessible.",
     "Restrict access to maintenance scripts."),

    ("/robots.txt",             "Robots.txt Exposed",             "Low",      3.1,
     "Robots.txt is accessible, revealing site structure.",
     "Review robots.txt for information disclosure."),

    ("/sitemap.xml",            "Sitemap Exposed",                 "Low",      3.1,
     "Sitemap is accessible, revealing site structure.",
     "Review sitemap for sensitive information."),

    ("/crossdomain.xml",        "Crossdomain Policy Exposed",     "Low",      3.1,
     "Crossdomain policy file is accessible.",
     "Review crossdomain policy for security."),

    ("/clientaccesspolicy.xml", "Silverlight Policy Exposed",      "Low",      3.1,
     "Silverlight client access policy is accessible.",
     "Review client access policy."),

    ("/.well-known/",           "Well-Known Directory Exposed",    "Low",      3.1,
     "Well-known directory is accessible.",
     "Review .well-known directory contents."),

    ("/.well-known/acme-challenge/", "ACME Challenge Exposed", "Low", 3.1,
     "ACME challenge directory is accessible.",
     "Ensure ACME challenge directory is properly secured."),

    # Additional paths (30+ more)
    ("/login",                  "Login Page Exposed",              "Low",      3.1,
     "A login page is publicly accessible.",
     "Implement rate limiting and account lockout."),

    ("/signup",                 "Signup Page Exposed",             "Low",      3.1,
     "A registration page is publicly accessible.",
     "Implement CAPTCHA and email verification."),

    ("/register",               "Registration Exposed",            "Low",      3.1,
     "A registration page is publicly accessible.",
     "Implement CAPTCHA and email verification."),

    ("/api",                    "API Endpoint Exposed",            "Low",      3.1,
     "An API endpoint is publicly accessible.",
     "Implement authentication on all API endpoints."),

    ("/api/",                   "API Directory Exposed",           "Low",      3.1,
     "API directory listing may be enabled.",
     "Disable directory listing on API directories."),

    ("/api/v1",                 "API v1 Endpoint Exposed",         "Low",      3.1,
     "API version 1 endpoint is publicly accessible.",
     "Implement authentication and rate limiting."),

    ("/api/v2",                 "API v2 Endpoint Exposed",         "Low",      3.1,
     "API version 2 endpoint is publicly accessible.",
     "Implement authentication and rate limiting."),

    ("/dev",                    "Development Interface Exposed",   "High",     7.5,
     "A development interface is publicly accessible.",
     "Restrict dev interfaces to internal networks."),

    ("/staging",                "Staging Environment Exposed",     "High",     7.5,
     "A staging environment is publicly accessible. Staging often has weaker security.",
     "Restrict staging access to internal networks."),

    ("/health",                 "Health Check Exposed",            "Low",      3.1,
     "A health check endpoint is publicly accessible.",
     "Restrict health checks to internal monitoring systems."),

    ("/healthz",                "Health Check Exposed",            "Low",      3.1,
     "A health check endpoint is publicly accessible.",
     "Restrict health checks to internal monitoring systems."),

    ("/actuator",               "Spring Boot Actuator Exposed",   "High",     7.5,
     "Spring Boot Actuator endpoints are exposed, revealing application internals, metrics, and environment.",
     "Disable Actuator in production or secure with authentication:\n  management.endpoints.web.exposure.exclude=*"),

    ("/actuator/health",        "Spring Boot Health Exposed",      "Low",      3.1,
     "Spring Boot health endpoint is accessible.",
     "Restrict Actuator endpoints to internal networks."),

    ("/actuator/env",           "Spring Boot Env Exposed",        "Critical", 9.8,
     "Spring Boot environment endpoint exposes all environment variables including secrets.",
     "Disable sensitive Actuator endpoints in production."),

    ("/actuator/actuator",      "Spring Boot Actuator Exposed",    "High",     7.5,
     "Spring Boot Actuator is exposed.",
     "Secure Actuator endpoints."),

    ("/swagger-ui.html",        "Swagger UI Exposed",              "Medium",   5.3,
     "Swagger UI documentation is publicly accessible.",
     "Restrict Swagger UI to internal networks."),

    ("/swagger/",               "Swagger Endpoint Exposed",        "Medium",   5.3,
     "Swagger API documentation endpoint is accessible.",
     "Restrict Swagger to authenticated users."),

    ("/api/swagger",            "API Swagger Exposed",             "Medium",   5.3,
     "API Swagger documentation is accessible.",
     "Restrict Swagger to internal networks."),

    ("/api/v1/swagger",         "API v1 Swagger Exposed",          "Medium",   5.3,
     "API version 1 Swagger docs are accessible.",
     "Restrict Swagger to internal networks."),

    ("/config/",                "Config Directory Exposed",        "High",     7.5,
     "Configuration directory is accessible, potentially exposing config files.",
     "Restrict access to configuration directories."),

    ("/config.js",              "JS Config Exposed",               "High",     7.5,
     "JavaScript configuration file is accessible, potentially exposing API keys.",
     "Move configuration from JS files to server-side."),

    ("/config.json",            "JSON Config Exposed",             "High",     7.5,
     "JSON configuration file is publicly accessible.",
     "Restrict access to configuration files."),

    ("/configuration",          "Configuration Endpoint Exposed",  "High",     7.5,
     "Configuration endpoint is publicly accessible.",
     "Restrict configuration endpoints."),

    ("/debug",                  "Debug Endpoint Exposed",         "Medium",   5.3,
     "A debug endpoint is publicly accessible, revealing application internals.",
     "Remove debug endpoints from production."),

    ("/telescope",              "Laravel Telescope Exposed",      "High",     7.5,
     "Laravel Telescope debug dashboard is publicly accessible.",
     "Restrict Telescope access in production."),

    ("/vapor",                  "Laravel Vapor Exposed",           "Medium",   5.3,
     "Laravel Vapor UI is publicly accessible.",
     "Restrict Vapor access to authorized users."),

    ("/nova",                   "Laravel Nova Exposed",           "Medium",   5.3,
     "Laravel Nova admin panel is publicly accessible.",
     "Restrict Nova access to authorized IPs."),

    ("/horizon",                "Laravel Horizon Exposed",        "Medium",   5.3,
     "Laravel Horizon queue monitoring is publicly accessible.",
     "Restrict Horizon access to authorized users."),

    ("/queues",                 "Queue Manager Exposed",           "Medium",   5.3,
     "Queue management interface is publicly accessible.",
     "Restrict queue management interfaces."),

    ("/metrics",                "Metrics Endpoint Exposed",        "Low",      3.1,
     "Application metrics endpoint is publicly accessible.",
     "Restrict metrics to internal monitoring."),

    ("/prometheus",             "Prometheus Metrics Exposed",      "Low",      3.1,
     "Prometheus metrics endpoint is publicly accessible.",
     "Restrict Prometheus metrics to internal networks."),

    ("/sitemap",                "Sitemap Endpoint Exposed",         "Low",      3.1,
     "Sitemap endpoint is accessible.",
     "Review sitemap for sensitive URLs."),

    ("/sitemap_index.xml",      "Sitemap Index Exposed",           "Low",      3.1,
     "Sitemap index file is accessible.",
     "Review sitemap for sensitive information."),

    ("/cgi-bin/",               "CGI Bin Exposed",                "High",     7.5,
     "CGI bin directory is accessible, potentially allowing remote code execution.",
     "Disable CGI if not needed. Restrict access to /cgi-bin/."),

    ("/cgi-bin/test.cgi",       "CGI Test Script Exposed",        "High",     7.5,
     "CGI test script is publicly accessible.",
     "Remove test CGI scripts from production."),

    ("/.npmrc",                 "NPM RC Exposed",                  "Medium",   5.3,
     "NPM configuration file is accessible, potentially containing registry auth tokens.",
     "Remove .npmrc from web root."),

    ("/.yarnrc",                "Yarn RC Exposed",                 "Medium",   5.3,
     "Yarn configuration file is accessible.",
     "Remove .yarnrc from web root."),

    ("/web.config",             "IIS Web Config Exposed",          "Medium",   5.3,
     "IIS web.config configuration file is accessible.",
     "Restrict access to web.config."),

    ("/web.xml",                "Java Web XML Exposed",            "Medium",   5.3,
     "Java web.xml configuration file is accessible.",
     "Restrict access to web.xml."),

    ("/struts/",                "Apache Struts Exposed",           "High",     7.5,
     "Apache Struts framework endpoint is accessible.",
     "Upgrade Struts to latest version."),

    ("/axis2/",                 "Axis2 Web Service Exposed",       "Medium",   5.3,
     "Apache Axis2 web service is accessible.",
     "Restrict access to Axis2."),

    ("/ws/",                    "Web Service Exposed",             "Medium",   5.3,
     "Web service endpoint is accessible.",
     "Restrict access to web services."),

    ("/soap/",                  "SOAP API Exposed",                "Medium",   5.3,
     "SOAP API endpoint is publicly accessible.",
     "Implement authentication on SOAP endpoints."),

    ("/index.php",              "PHP Index Exposed",               "Low",      3.1,
     "PHP index file is accessible.",
     "Ensure proper configuration."),

    ("/index.html",             "HTML Index Exposed",              "Low",      3.1,
     "HTML index file is accessible.",
     "Ensure proper configuration."),

    ("/index.jsp",              "JSP Index Exposed",               "Low",      3.1,
     "JSP index file is accessible.",
     "Ensure proper configuration."),

    ("/default.aspx",           "ASP.NET Default Exposed",         "Low",      3.1,
     "ASP.NET default page is accessible.",
     "Ensure proper configuration."),

    ("/default.asp",            "ASP Default Exposed",             "Low",      3.1,
     "ASP default page is accessible.",
     "Ensure proper configuration."),
]


class DirectoryScanner(BaseScanner):
    SCANNER_NAME = "Sensitive Directory & File Scanner"
    _SCANNER_KEY = "directory"

    def _bypass_403(self, url, path):
        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"Client-IP": "127.0.0.1"},
            {"X-Forwarded-Host": "127.0.0.1"}
        ]

        bypass_paths = [
            path.replace("/", "//", 1),
            path.replace("/", "/%2e/", 1),
            f"{path}/.",
            f"{path}%20",
            f"{path}%00",
            f"{path}..;/"
        ]

        base = self.target.rstrip("/")

        for headers in bypass_headers:
            headers["User-Agent"] = "LarShield/2.0 Bypass"
            body, status, _ = self._make_request(
                url, headers=headers, timeout=5, return_response_obj=True,
            )
            if status == 200:
                return True, f"Header Bypass ({list(headers.keys())[0]})"

        for b_path in bypass_paths:
            b_url = f"{base}{b_path}"
            body, status, _ = self._make_request(
                b_url, timeout=5, return_response_obj=True,
            )
            if status == 200:
                return True, f"Path Permutation ({b_path})"

        return False, None

    def _classify_status(self, status):
        if status == 200:
            return "exposed"
        elif status in (301, 302, 307, 308):
            return "redirect"
        elif status == 401:
            return "auth_required"
        elif status == 403:
            return "forbidden"
        elif status in (404, 410):
            return "not_found"
        elif status == 429:
            return "rate_limited"
        elif status in (500, 502, 503):
            return "server_error"
        return "unknown"

    def run(self):
        self.log("INFO", f"[DirScan] Scanning {len(SENSITIVE_PATHS)} sensitive paths on {self.domain}...")
        exposed_count = 0
        base = self.target.rstrip("/")

        requests_list = []
        for path, title, severity, cvss, description, remediation in SENSITIVE_PATHS:
            url = f"{base}{path}"
            req = {
                "url": url,
                "headers": {"User-Agent": "LarShield/2.0"},
                "timeout": 6,
                "_meta": (path, title, severity, cvss, description, remediation),
            }
            requests_list.append(req)

        results = self._make_async_requests(requests_list, max_workers=20)

        for req, body, status in results:
            meta = req.get("_meta")
            if not meta:
                continue
            path, title, severity, cvss, description, remediation = meta
            url = req["url"]

            classification = self._classify_status(status)

            if classification == "exposed":
                content_len = len(body) if body else 0
                if content_len > 5:
                    # PHASE 1: Suppress if response is the site's SPA/404 catch-all
                    if self._is_baseline(status, body):
                        self.log("INFO", f"[DirScan] SUPPRESSED (baseline match, {content_len}B): {url}")
                    else:
                        lvl = "CRITICAL" if cvss >= 9.0 else "WARNING"
                        self.log(lvl, f"[DirScan] EXPOSED (HTTP {status}, {content_len}B): {url}")
                        self.add_vuln(
                            title=title, severity=severity, category="Exposed Files",
                            cvss_score=cvss,
                            description=f"{description}\n\nExposed at: {url}",
                            remediation=remediation,
                            evidence=f"HTTP {status}, {content_len} bytes",
                            response_details=f"HTTP {status} - {classification}",
                            confidence="Confirmed",
                        )
                        exposed_count += 1
            elif classification == "redirect":
                self.log("INFO", f"[DirScan] Redirect (HTTP {status}): {url}")
            elif classification == "auth_required":
                self.log("INFO", f"[DirScan] Auth required (HTTP {status}): {url}")
            elif classification == "forbidden":
                bypassed, method = self._bypass_403(url, path)
                if bypassed:
                    self.log("CRITICAL", f"[DirScan] 403 BYPASSED ({method}): {url}")
                    self.add_vuln(
                        title=title, severity=severity, category="Exposed Files",
                        cvss_score=cvss,
                        description=f"{description}\n\nExposed at: {url}\nBypass method: {method}",
                        remediation=remediation,
                        evidence=f"403 bypassed via {method}",
                        response_details=f"HTTP 403 bypassed to 200",
                        confidence="Confirmed",
                    )
                    exposed_count += 1
                else:
                    self.log("INFO", f"[DirScan] Protected (HTTP {status}): {url} \u2714")
            elif classification == "rate_limited":
                self.log("WARNING", f"[DirScan] Rate limited (HTTP {status}): {url}")
            elif classification == "not_found":
                self.log("SUCCESS", f"[DirScan] Not found: {path} \u2714")
            else:
                self.log("INFO", f"[DirScan] Status {status}: {url}")

        self.log("SUCCESS" if exposed_count == 0 else "WARNING",
                 f"[DirScan] Scan complete. {exposed_count} exposed path(s) found.")
        return self.vulns
