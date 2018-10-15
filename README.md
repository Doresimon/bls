# Boneh Lynn Shacham Signature (BLS)

## BLS short signature

[Short signatures from the Weil pairing]()

Dan Boneh, Ben Lynn, and Hovav Shacham

__Abstract.__ We introduce a short signature scheme based on the 
Computational Dffie-Hellman assumption on certain elliptic and hyper-elliptic
curves. The signature length is half the size of a DSA signature for a
similar level of security. Our short signature scheme is designed for 
systems where signatures are typed in by a human or signatures are sent
over a low-bandwidth channel.

## BLS aggragated signature based on BLS short signature

[Aggregate and Verifiably Encrypted Signatures from Bilinear Maps]()

Dan Boneh
dabo@cs.stanford.edu,
Craig Gentry
cgentry@docomolabs-usa.com,
Ben Lynn
blynn@cs.stanford.edu,
Hovav Shacham
hovav@cs.stanford.edu,

__Abstract__
An aggregate signature scheme is a digital signature that supports aggregation: Given n
signatures on n distinct messages from n distinct users, it is possible to aggregate all these
signatures into a single short signature. This single signature (and the n original messages)
will convince the verifier that the n users did indeed sign the n original messages (i.e., user i
signed message Mi for i = 1,...,n). In this paper we introduce the concept of an aggregate
signature, present security models for such signatures, and give several applications for aggregate
signatures. We construct an efficient aggregate signature from a recent short signature scheme
based on bilinear maps due to Boneh, Lynn, and Shacham. Aggregate signatures are useful
for reducing the size of certificate chains (by aggregating all signatures in the chain) and for
reducing message size in secure routing protocols such as SBGP. We also show that aggregate
signatures give rise to verifiably encrypted signatures. Such signatures enable the verifier to test
that a given ciphertext C is the encryption of a signature on a given message M. Verifiably
encrypted signatures are used in contract-signing protocols. Finally, we show that similar ideas
can be used to extend the short signature scheme to give simple ring signatures.