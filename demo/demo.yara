/*
 * 	Search for traces of secret domains
 */
rule SecretDomain
{
    strings:
        $sec_domain = "gmail.com"   nocase wide ascii

    condition:
        any of them
}

/* 
 * Search for traces of secret DNS
 */
rule SecretDNS
{
    strings:
        $sec_dns = "8.8.8.8"    wide ascii

    condition:
        any of them
}