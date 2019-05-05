# CALDERA plugin: Adversary

This plugin contains:
* The original CALDERA mode in plugin form
* This includes multiple REST API endpoints, an agent and a RAT and a GUI component. 

This plugin will allow you to run operations on Windows hosts only.

## Requirements

To use this plugin, you must have a Mongo database installed and running locally.
Detailed MongoDB Server installation instructions can be found here: 
https://docs.mongodb.com/manual/installation/#mongodb-community-edition-installation-tutorials

This plugin also requires that you load the GUI plugin with it.

## BSF

Operations run through the Adversary Plugin generate logs in the BRAWL Shared Format (BSF). More information about 
this format can be found <a href="https://github.com/mitre/brawl-public-game-001#bsf">here</a>. Please note 
that CALDERA's BSF download produces an ordered collection of BSF objects (other header information, such as 'game_id' 
and 'bsf_version', is handled elsewhere). Excerpts from an example CALDERA generated BSF log are documented here as an 
example of how to read and reference the format.
```
[
    {
        "id": "b083958c-e052-4c04-b466-1cab8a4d819e",           # Entry ID 
        "nodetype": "event",                                    # Entry Type (BSF event)
        "host": "dc.caldera.local",                             # The host involved
        "object": "process",                                    # What was involved
        "action": "create",                                     # What happened
        "happened_after": "2019-03-04T21:12:24.575720+00:00",   # When did the event occur (start)
        "fqdn": "dc.caldera.local",                             # FQDN of the host
        "ppid": 2968,                                           # PPID involved
        "pid": 2596,                                            # PID involved
        "command_line": "powershell -command -",                # commandline captured
        "happened_before": "2019-03-04T21:12:29.480753+00:00"   # When did the event occur (end)
    },                                                          #
    {                                                           #
        "id": "ee802ac0-e757-4a81-80ea-ea294eb47f6b",           # Entry ID 
        "nodetype": "step",                                     # Entry Type ('step' is a CALDERA step)
        "attack_info": [                                        # Step ATT&CK taxonomy information
            {                                                   #
                "technique_id": "T1018",                        # Associated technqiue ID
                "technique_name": "Remote System Discovery",    # Associated technique Name
                "tactic": [                                     # Associated tactics
                    "Discovery"                                 #
                ]                                               #
            },                                                  #
            {                                                   #
                "technique_id": "T1086",                        #
                "technique_name": "PowerShell",                 #
                "tactic": [                                     #
                    "Execution"                                 #
                ]                                               #
            },                                                  #
            {                                                   #
                "technique_id": "T1064",                        #
                "technique_name": "Scripting",                  #
                "tactic": [                                     #
                    "Defense Evasion",                          #
                    "Execution"                                 #
                ]                                               #
            },                                                  #
            {                                                   #
                "technique_id": "T1106",                        #
                "technique_name": "Execution through API",      #
                "tactic": [                                     #
                    "Execution"                                 #
                ]                                               #
            }                                                   #
        ],                                                      #
        "events": [                                             #
            "b083958c-e052-4c04-b466-1cab8a4d819e"              # Associated step event
        ],
        "key_technique": "T1018",                               # Primary technique involved
        "key_event": "b083958c-e052-4c04-b466-1cab8a4d819e",    # Primary event associated
        "host": "dc.caldera.local",                             # Host involved
        "time": "2019-03-04T21:12:27.028237+00:00",             # Time step occured
        "description": "Enumerating all computers in the domain"# Step description
    },                                                          #
    ...                                                         #
    {                                                           #
        "id": "8bedb0b2-b566-4a5b-9b0a-f24c81a262cd",           # Entry ID
        "steps": [                                              # Entry Associated Steps
            "ee802ac0-e757-4a81-80ea-ea294eb47f6b",             #
            "3c9395ae-71f5-4109-94cb-1cc3ca0b6cdb",             #
            "1a5584c3-4081-4922-b957-e2e1b32b1180",             #
            "b3223370-30d7-4484-a18e-d6668bf8d11e",             #
            "9934276d-968c-4584-9e37-c1d81e7c0753",             #
            "db1e2188-5c9b-4ca1-aef5-c9e0d2ce415b",             #
            "f5598a0d-6c0e-4766-9a8f-c25f69e2270b",             #
            "0aa4f283-aa07-4024-9544-e64644e5bcc6",             #
            "bbe654be-edc8-4823-83e6-908380abb1e5",             #
            "d218c2aa-50ef-483c-b63a-33e1fcbee459",             #
            "330526e2-7a15-42b8-9f9c-9bc1ab30a1ad",             #
            "1d11a093-c4eb-4388-865a-b1c4c83e5152",             #
            "a196bad2-8310-4bc7-b5a6-e85b6a60e110",             #
            "2390973a-0afe-4206-8179-6bed0e8d6651"              #   
        ],                                                      #
        "nodetype": "operation"                                 # Entry Type (CALDERA Operation)
    }
]
```
