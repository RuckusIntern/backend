SELECT json_object('package', package, 'cve_name', cve_name, 'severity', cve_name, 'cvss_score', cvss_score, 'cvss_status', cvss_status, 'cve_url', cve_url, 'vulnerabilities_status', vulnerabilities_status, 'vulnerabilities_url', vulnerabilities_url, 'platform', platform, 'release_image_name', release_image_name, 'package_name', package_name, 'package_version', package_version, 'package_release', package_release, 'comment', comment, 'solution', solution, 'date', date, 'commentator', commentator ) FROM CVE;

select package, cve_name, severity, cvss_score, cvss_status, cve_url, vulnerabilities_status, vulnerabilities_url, platform, release_image_name, package_name, package_version, package_release, comment, solution, date, commentator from CVE;

select * from CVE;

UPDATE CVE SET comment = 'test', solution = 'test', commentator = 'ruckusIntern' WHERE package = 'acl-2.2.51-14.el7';