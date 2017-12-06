# ctguard
Be notified by cron if a new certificate emerges on a domain of interest

## Usage
Simply use the program with the domain names as parameters

### Example Crontab entry
00 07 * * * ~/tools/ctguard/ctguard.py yourdomain.com yourseconddomain.org

### Prevent initial flood
CTguard will report new instances of certificates, so if you never used it for a particular domain it will report ALL certifictes.
You can prevent this by running it manully once for that domain eg: ./ctguard.py my-new-domain-to-watch-ct.net


