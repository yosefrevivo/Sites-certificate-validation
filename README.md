Security Project 2 - 
Yosef Revivo 318202645

The current project comes to simulate and introduce a mechanism for generating and verifying site certificates.
It is built so that each server is a site in itself that can be init by -- npm start -- cmd in the terminal.

In his initiation,
we produce for him (1) a private and (2) a public key.
In addition, each server knows at the initialization the only reliable main source of certificate production (i.e root at the code).

From each server, you can request to sign your site, and also request the certificate path.

In addition,
each server has an authentication function for a given set of certificates,
The function iterate all over the given certifications path, and checks that the path is valid for the known issuer root.

So in fact when we connect between different servers we can verify if they do have authentication.
In addition, each server can sign on to another server and then return the full signature authentication path. 