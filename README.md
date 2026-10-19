# Our Advice For Teams

The more milestones your team completes, the more competitive your submission will be. If you are unsure where to start, we recommend that teams begin in order:

    1. Block/header data structures and serialization
    2. State data structures and serialization
    3. In-memory DB and Merklization
    4. Non-PVM block execution/state-transition
    5. PVM instancing, execution and host-functions
    6. Block-import tests

# Disclaimers
1. trie.py inspired from merkle.py
2. using jamdot's bandersnatch vrf.

# TODO
1. Some errors (not present in test vectors) in Safrole remain unhandled
2. Move spec_globals out of header_codec
4. Many of the inputs to STF components need to be readonly e.g. accumulation_queue and accumulation_history in reports_stf

# Queries
1. Shouldn't the case of account service id not found be handled in stf/preimage vectors?