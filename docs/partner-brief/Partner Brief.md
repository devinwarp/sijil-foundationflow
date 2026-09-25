# Sijill — Partner Brief

*For integrators and platform vendors bidding government AI work. One page. Hand it over on the day, don't email it after.*

## What it is

Sijill seals a tamper-evident record of every LLM inference — model version, execution node and location, policy in force, approval reference, input and output hashes — on infrastructure the customer owns. An independent verifier proves the chain is unbroken. The output is an audit report an assurance function can hand to a third party.

## The accounts this is for

**Not the ones you take whole.** Where a customer adopts your platform end to end, they get lineage and audit with it. Sijill is redundant there and we will say so.

**The ones you can't.** Customers who have already built their own inference stack, or run a mixed estate they will not replace, have no attestation path. Hyperscaler confidential-inference services do not reach infrastructure the customer owns. Replacing a working stack to obtain an audit trail is not a trade anyone makes — so the requirement goes unmet and the bid gets harder.

Sijill covers those accounts without displacing anything you would otherwise sell.

## What it does for your bid

|  |  |
| --- | --- |
| Fills an evidence requirement | Without asking the customer to replace their inference stack |
| Runs on their hardware | Bare metal, private cloud, mixed estate. No hyperscaler dependency |
| Sits under your delivery | You hold the customer relationship and the contract |
| UAE-based provider | Supports local content and sovereignty requirements in the response |

## What we need from the environment

- A network path in front of the existing model endpoint
- Read access to model version identifiers
- Storage for the record chain, on their infrastructure
- One named policy owner on the customer side

No change to the model, the application, or the serving runtime.

## What we commit to

- Technical content for the compliance and assurance sections of your response
- A named engineer through deployment
- Deployment inside your delivery, under your customer relationship
- No direct approach to the account outside the partnership

## Honest boundaries

Sijill proves records have not been altered since sealing. Hardware root of trust — binding the seal to the silicon — is roadmap, built on NVIDIA and TEE attestation primitives rather than replacing them. We say this to customers too.

## Next step

Name one live or upcoming opportunity where the customer keeps their own inference stack. We will build the technical response section for it at no cost, before any commercial agreement.

---

**FoundationFlow** · Shameer Thaha, CEO · foundationflow.ai
