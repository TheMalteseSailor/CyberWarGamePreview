from typing_extensions import Required
from CyberWarGame import getResponse
from PlayerUtils import backgroundTaskWorker
import threading


# The logic to handle the task decisions will need to take the HackerTeam object and the TargetNetwork object so that
# modifications can be made between the two that a

#decision_type = Decision_logic.scan_system
'''
decision_struct = {
    "decision_type": "",
    "context":"",
    "targetNetwork":"",
    "HackingTeam":"",
    "TargetSystem":"",
    }
'''

def baseDecisionHandler(decision_struct) -> None:
    # The HackingTeam Object is used to ascertain if certain tool reqirments are met.

    # need to convert decision type from string to identify the specific decision table dictionary.
    number_of_options = 0
    decision_type = decision_struct["decision_type"]
    context = decision_struct["context"]
    if context.burnedout:
        getResponse((decision_struct["HackingTeam"]).player, context, 'burnedout')     
        return
    # check is down here so user can plan actions for NPCs that are enumbered.
    if context.encumbered_timer_seconds != 0:
        getResponse((decision_struct["HackingTeam"]).player, context, 'encumbered')        
        # check to see if the player can take on the task
        return
    #for index, item in enumerate(acquire_redirector):
    number_of_options = 0
    for index, item in enumerate(decision_type):
        if 'title' in item:
            pass
        if 'option' in item:
            print("")
            print(f"[+] Option {number_of_options}")
            #for item in acquire_redirector[f"option {index}"].items():
            for item in decision_type[f"option {number_of_options}"].items():
                if 'definition' in item:    
                    print(f" -- Definition:")
                    print(f"     \__ {item[1]}")
                elif 'required skill values' in item:
                    print(" -- Skill Requirements:  ")
                    for thing in item[1].items():
                        print(f"     \__ {thing[0]}: {str(thing[1])}")
                        
                elif "chance" in item:
                    print(f" -- Chance: Requires {item[1][1]}+ of D{item[1][0]}")
                    
                elif "bonus_chance" in item:
                    # I'm going to need to pull a definition of what the bonus to display 
                    print(f" -- Bonus Chance: {item[1]}")
               
                elif "failure_state" in item:
                    # I'm going to need to pull a definition of what the failure to display 
                    print(f" -- Failure state: {item}")

                elif "time cost" in item:
                    print(f" -- Failure Cost: {item[1]}")

                else:
                    pass
                    #print("[!] ERROR: Illegal decision value!")
        number_of_options += 1

            
    while True:
        decision = input(f"[{context.name}] [cancel|#] choice? ")
        if decision.lower() == 'cancel':
            return
        decision = decision.strip(" ").split(" ")[0] 
        try:
            print(f"[DEBUG] decison: {decision}")
            int(decision)
        except:
            print(f"[DEBUG] decison: {decision}")
            getResponse((decision_struct["HackingTeam"]).player, context, 'which_one')
            return

        if (int(decision) < 1) or (int(decision) > number_of_options): 
            getResponse((decision_struct["HackingTeam"]).player, context, 'not_valid')
            return
        
        skill_fail_check = False
        while True:
            if context.programming < decision_type[f"option {decision}"]["required skill values"]["programming"]:
                print(f"[Narrator] insufficient skill in programming.")
                have = decision_type[f"option {decision}"]["required skill values"]["programming"]
                print(f"    \__ You need: {have}")
                print(f"    \__ You have: {context.programming}")               
                skill_fail_check = True
            if context.scripting < decision_type[f"option {decision}"]["required skill values"]["scripting"]:
                print(f"[Narrator] insufficient skill in scripting.")
                have = decision_type[f"option {decision}"]["required skill values"]["scripting"]
                print(f"    \__ You need: {have}")
                print(f"    \__ You have: {context.scripting}")
                skill_fail_check = True
            if context.network_exploitation < decision_type[f"option {decision}"]["required skill values"]["network exploitation"]:
                print(f"[Narrator] insufficient skill in network exploitation.")
                have = decision_type[f"option {decision}"]["required skill values"]["network exploitation"]
                print(f"    \__ You need: {have}")
                print(f"    \__ You have: {context.network_exploitation}")
                skill_fail_check = True
            if context.exploit_development < decision_type[f"option {decision}"]["required skill values"]["exploit development"]:
                print(f"[Narrator] insufficient skill in exploit development.")
                have = decision_type[f"option {decision}"]["required skill values"]["exploit development"]
                print(f"    \__ You need: {have}")
                print(f"    \__ You have: {context.exploit_development}")
                skill_fail_check = True
            break

        if skill_fail_check == True:
            print("[Narrator] Choose another option.")
            continue
        


        ##############
        # Threading to manange the enucumbered timer and follow on results. 
        # I may need to build a mailbox/messagebox for the player to retrieve out of band messages from the NPCs

        final_decision_struct = { "title" : decision_struct["decision_type"]['title']} | decision_type[f"option {decision}"]

        # Dice roll occur here
        num_sided_die = decision_type[f"option {decision}"]["chance"][0]
        req_num_for_success = decision_type[f"option {decision}"]["chance"][1]
        roll_result = 0
        if num_sided_die == 20:
            roll_result = context._rollD20()
        elif num_sided_die == 12:
            roll_result = context._rollD12()
        elif num_sided_die == 6:
            roll_result = context._rollD6()


        if roll_result < req_num_for_success:
            print("[Narrator] Failed dice roll for initial success.")
            print(f"    \__ Needed: {req_num_for_success} on a D{num_sided_die}")
            print(f"    \__ Your Roll: {roll_result}")
            # This get response is going to look weird if the play's context returns. It returns something that doesn't make any sense.
            getResponse((decision_struct["HackingTeam"]).player, context, 'failed')
            context.incrementBurnoutCounter()
            ########
            final_decision_struct["failure_state"] = True
            # There still needs to be a background worker thread spawned to take care of the failure case.
            # specifically if there is additional encumberment time
            print(f"[DEBUG] Calling background task worker thread from failure status.")
            test = threading.Thread(target=backgroundTaskWorker, args=(context, decision_struct["HackingTeam"], final_decision_struct,))
            test.start()
            test.join()
            ########
            return

        print(f"[Narrator] Dice roll Succeded.")
        print(f"    \__ Needed: {req_num_for_success} on a D{num_sided_die}")
        print(f"    \__ Your Roll: {roll_result}")
        print()
        
        # This thread will set the encumered time and count down and perform 'final' tasks
        # or checks when the timer reaches 1 second left. 
        #       1 second left prevents a race condition with the user to perform tasks before
        #       follow on commands are run.


        #test = threading.Thread(target=backgroundTaskWorker, args=(context, final_decision_struct,)).start()
        print(f"[DEBUG] Calling background task worker thread from success status.")
        test = threading.Thread(target=backgroundTaskWorker, args=(context, decision_struct["HackingTeam"], final_decision_struct,))
        test.start()
        test.join()
        
        

        return

# functions were defined so that function calls could be placed as values in the "outcome_reference" key


# this decision table needs expanding later when the game is more mature.
def get_scan_network_external(decision_struct) -> dict:
    scan_network_external = {
        "title": "External target network scan.",
        "option 1" : {
        "definition" : "Use aggressive nmap scan against all ports of the target's externally facing systems.",
        "required skill values" : {
            "exploit development": 0,
            "network exploitation" : 1,
            "programming" : 0,
            "scripting": 1
            },
        "time cost": 2,
        # (# of dice sides, value to achieve success)
        "chance": (20, 5),
        # Redirector + 1
        #"success bonus": "",
        "bonus_chance": (0,0),
        "bonus_define": "None",
        "bonus_type": [],
        "bonus_reference": [],
        # Add 2 minutes to a hacker's encumbered timer.
        #"failure cost": "",
        "failure_state": False,
        "failure_define": "Increment hacker's burnout counter by one.",
        "failure_reference": [(decision_struct["context"].incrementBurnoutCounter,[])],
        # outcome_reference is the function that is executed upon success.
        #"outcome_args": [],
        "outcome_reference": [(decision_struct["targetNetwork"].results_enumerateEdgeNodes, [])]
        },
        "option 2" : {
        "definition" : "A slower, but still broad scan of the target's externally facing systems.",
        "required skill values" : {
            "exploit development": 0,
            "network exploitation" : 2,
            "programming" : 0,
            "scripting": 1
            },
        "time cost": 3,
        # (# of dice sides, value to achieve success)
        "chance": (20, 8),
        # Redirector + 1
        #"success bonus": "",
        "bonus_chance": (10,decision_struct["context"]._rollD20()),
        "bonus_define": "Gain an additional skill point towards Network Exploitation.",
        "bonus_type": ["network_exploitation"],
        "bonus_reference": [decision_struct["context"].recvdTaskBonus],
        # Add 2 minutes to a hacker's encumbered timer.
        #"failure cost": "",
        "failure_state": False,
        "failure_define": "Increment hacker's burnout counter by one.",
        "failure_reference": [(decision_struct["context"].incrementBurnoutCounter,[])],
        # outcome_reference is the function that is executed upon success.
        #"outcome_args": [],
        "outcome_reference": [(decision_struct["targetNetwork"].results_enumerateEdgeNodes, [])]
        },
    }
    return scan_network_external

def get_acquire_redirector(decision_struct) -> dict:
    acquire_redirector = {
        "title": "Acquire redirector(s).",
        "option 1" : {
        "definition" : "Use a wellknown VPS service with gift card.",
        "required skill values" : {
            "exploit development": 0,
            "network exploitation" : 1,
            "programming" : 0,
            "scripting": 1
            },
        "time cost": 2,
        "chance": (20, 2),
        "bonus_chance": (0,0),
        "bonus_define": "None",
        "bonus_type": [],
        "bonus_reference": [],
        "failure_state": False,
        "failure_define": "Increment hacker's burnout counter by one. And lose an already existing redirector",
        "failure_reference": [(decision_struct["context"].incrementBurnoutCounter,[]),
                              (decision_struct["HackingTeam"].decrement_redirectors,[])],
        #"outcome_args": [],
        "outcome_reference": [(decision_struct["HackingTeam"].increment_redirector, [])]
        },
        "option 2" : {
        "definition" : "Use a less known, but kinda sketchy VPS provider. Has chance for more than one redirector acquired.",
        "required skill values" : {
            "exploit development": 0,
            "network exploitation" : 2,
            "programming" : 0,
            "scripting": 1
            },
        "time cost": 2,
        "chance": (0,0),
        "bonus_chance": (10,decision_struct["context"]._rollD20()),
        "bonus_define": "None",
        "bonus_type": ["personality_bonus"],
        "bonus_reference": [decision_struct["context"].recvdTaskBonus],
        "failure_state": False,
        "failure_define": "Increment hacker's burnout counter by one. And lose an already existing redirector",
        "failure_reference": [(decision_struct["context"].incrementBurnoutCounter,[]),
                              (decision_struct["HackingTeam"].decrement_redirectors,[])],
        #"outcome_args": [],
        "outcome_reference": [(decision_struct["HackingTeam"].increment_redirector, []), 
                              (decision_struct["HackingTeam"].increment_redirector, [])]
        },
        "option 3" : {
        "definition" : "Use tumbled bitcoin to purchase reputable normie VPS.",
        "required skill values" : {
            "exploit development": 0,
            "network exploitation" : 2,
            "programming" : 0,
            "scripting": 2
            },
        "time cost": 2,
        "chance": (20, 8),
        "bonus_chance": (15,decision_struct["context"]._rollD20()),
        "bonus_define": "Potentially gain personality bonus.",
        "bonus_type": ["personality_bonus"],
        "bonus_reference": [decision_struct["context"].recvdTaskBonus],
        "failure_state": False,
        "failure_define": "Increment hacker's burnout counter by one.",
        "failure_reference": [(decision_struct["context"].incrementBurnoutCounter,[])],
        #"outcome_args": [],
        "outcome_reference": [(decision_struct["HackingTeam"].increment_redirector, [])]
        },
        "option 4" : {
        "definition" : "Purchase verified anonymous VPS with Monero. Has chance to aquire more than one redirector.",
        "required skill values" : {
            "exploit development": 0,
            "network exploitation" : 3,
            "programming" : 0,
            "scripting": 2
            },
        "time cost": 2,
        "chance": (20, 10),
        "bonus_chance": (10,decision_struct["context"]._rollD20()),
        "bonus_define": "Potentially gain personality bonus.",
        "bonus_type": ["personality_bonus"],
        "bonus_reference": [decision_struct["context"].recvdTaskBonus],
        "failure_state": False,
        "failure_define": "Increment hacker's burnout counter by one.",
        "failure_reference": [([decision_struct["context"].incrementBurnoutCounter],[])],
        #"outcome_args": [],
        "outcome_reference": [(decision_struct["HackingTeam"].increment_redirector, []), 
                              (decision_struct["HackingTeam"].increment_redirector, [])]
        },
    }
    return acquire_redirector

def get_develop_capability(decision_struct, capability_details, skill_requirements) -> dict:
    ########
    # capability_details: tool or exploit construction details
    # skill_requirements: values specific for exploit or tool task execution
    # skill_requirements = PlayerUtils.hackingTeam._values_*DevelopmentDecision() 
    #
    ########
    develop_capability = {
        "title" : f"Develop {capability_details['cape_type']} {capability_details['cape_category']} for {capability_details['platform']}.",
        "option 1" : {
        "definition" : "Lower skilled effort with longer time requirements | (User mode)",
        "required skill values" : {
            "exploit development": skill_requirements["option 1"]["required skill values"]["exploit development"],
            "network exploitation" : skill_requirements["option 1"]["required skill values"]["network exploitation"],
            "programming" : skill_requirements["option 1"]["required skill values"]["programming"],
            "scripting": skill_requirements["option 1"]["required skill values"]["scripting"]
            },
        "time cost": skill_requirements["option 1"]["time cost"],
        # (# of dice sides, value to achieve success)
        "chance": (20, 5),
        # Redirector + 1
        #"success bonus": "",
        "bonus_chance": (0,0),
        "bonus_define": skill_requirements["option 1"]["bonus_define"],
        "bonus_type": [],
        "bonus_reference": [],
        # Add 2 minutes to a hacker's encumbered timer.
        #"failure cost": "",
        "failure_state": False,
        "failure_define": "Increment hacker's burnout counter by one.",
        "failure_reference": [(decision_struct["context"].incrementBurnoutCounter,[])],
        # outcome_reference is the function that is executed upon success.
        #"outcome_args": [capability_details],
        "outcome_reference": [(decision_struct["context"].developCapability, [capability_details,skill_requirements["option 1"]["outcome_args"]])]
        },
        "option 2" : {
        "definition" : "Intermediate skilled effort with shorter, but still longer time requirements | (Limited Service)",
        "required skill values" : {
            "exploit development": skill_requirements["option 2"]["required skill values"]["exploit development"],
            "network exploitation" : skill_requirements["option 2"]["required skill values"]["network exploitation"],
            "programming" : skill_requirements["option 2"]["required skill values"]["programming"],
            "scripting": skill_requirements["option 2"]["required skill values"]["scripting"]
            },
        "time cost": skill_requirements["option 2"]["time cost"],
        # (# of dice sides, value to achieve success)
        "chance": (20, 8),
        # Redirector + 1
        #"success bonus": "",
        "bonus_chance": (10,decision_struct["context"]._rollD20()),
        "bonus_define": skill_requirements["option 2"]["bonus_define"],
        "bonus_type": ["network_exploitation"],
        "bonus_reference": [decision_struct["context"].recvdTaskBonus],
        # Add 2 minutes to a hacker's encumbered timer.
        #"failure cost": "",
        "failure_state": False,
        "failure_define": "Increment hacker's burnout counter by one.",
        "failure_reference": [(decision_struct["context"].incrementBurnoutCounter,[])],
        # outcome_reference is the function that is executed upon success.
        #"outcome_args": [capability_details],
        "outcome_reference": [(decision_struct["context"].developCapability, [capability_details,skill_requirements["option 2"]["outcome_args"]])]        },
        "option 3" : {
        "definition" : "Advanced skilled effort with acceptable time requirements. | (System)",
        "required skill values" : {
            "exploit development": skill_requirements["option 3"]["required skill values"]["exploit development"],
            "network exploitation" : skill_requirements["option 3"]["required skill values"]["network exploitation"],
            "programming" : skill_requirements["option 3"]["required skill values"]["programming"],
            "scripting": skill_requirements["option 3"]["required skill values"]["scripting"]
            },
        "time cost": skill_requirements["option 3"]["time cost"],
        # (# of dice sides, value to achieve success)
        "chance": (20, 8),
        # Redirector + 1
        #"success bonus": "",
        "bonus_chance": (10,decision_struct["context"]._rollD20()),
        "bonus_define": skill_requirements["option 3"]["bonus_define"],
        "bonus_type": ["network_exploitation"],
        "bonus_reference": [decision_struct["context"].recvdTaskBonus],
        # Add 2 minutes to a hacker's encumbered timer.
        #"failure cost": "",
        "failure_state": False,
        "failure_define": "Increment hacker's burnout counter by one.",
        "failure_reference": [(decision_struct["context"].incrementBurnoutCounter,[])],
        # outcome_reference is the function that is executed upon success.
        #"outcome_args": [capability_details],
        "outcome_reference": [(decision_struct["context"].developCapability, [capability_details,skill_requirements["option 3"]["outcome_args"]])]
        },
        "option 4" : {
        "definition" : "Expert skilled effort with short time requirements. | (Kernel)",
        "required skill values" : {
            "exploit development": skill_requirements["option 4"]["required skill values"]["exploit development"],
            "network exploitation" : skill_requirements["option 4"]["required skill values"]["network exploitation"],
            "programming" : skill_requirements["option 4"]["required skill values"]["programming"],
            "scripting": skill_requirements["option 4"]["required skill values"]["scripting"]
            },
        "time cost": skill_requirements["option 4"]["time cost"],
        # (# of dice sides, value to achieve success)
        "chance": (20, 8),
        # Redirector + 1
        #"success bonus": "",
        "bonus_chance": (10,decision_struct["context"]._rollD20()),
        "bonus_define": skill_requirements["option 4"]["bonus_define"],
        "bonus_type": ["network_exploitation"],
        "bonus_reference": [decision_struct["context"].recvdTaskBonus],
        # Add 2 minutes to a hacker's encumbered timer.
        #"failure cost": "",
        "failure_state": False,
        "failure_define": "Increment hacker's burnout counter by one.",
        #"failure_reference": [decision_struct["context"].incrementBurnoutCounter],
        "failure_reference": [(decision_struct["context"].incrementBurnoutCounter,[])],
        # outcome_reference is the function that is executed upon success.
        #"outcome_args": [capability_details],
        "outcome_reference": [(decision_struct["context"].developCapability, [capability_details,skill_requirements["option 4"]["outcome_args"]])]
        }
    }
    return develop_capability

def get_exploit_system(decision_struct, exploit_details, skill_requirements) -> dict:
    exploit_system = {
        "title": "Throw exploit at a target.",
        "option 1" : {
        "definition" : "",
        "required skill values" : {
            "exploit development": 0,
            "network exploitation" : 1,
            "programming" : 0,
            "scripting": 1
            },
        "time cost": 2,
        # (# of dice sides, value to achieve success)
        "chance": (20, 5),
        # Redirector + 1
        #"success bonus": "",
        "bonus_chance": (0,0),
        "bonus_define": "None",
        "bonus_type": [],
        "bonus_reference": [],
        # Add 2 minutes to a hacker's encumbered timer.
        #"failure cost": "",
        "failure_state": False,
        "failure_define": "Increment hacker's burnout counter by one. Failures during exploit can happen for many reasons.",
        "failure_reference": [(decision_struct["context"].incrementBurnoutCounter,[])] + skill_requirements["option 1"]["failure_reference"],
        "failure_message": [skill_requirements["option 1"]["failure_message"]],
        # outcome_reference is the function that is executed upon success.
        #"outcome_args": skill_requirements["option 1"]["outcome_args"],
        #"outcome_reference": [(skill_requirements["option 1"]["outcome_reference"][0], skill_requirements["option 1"]["outcome_args"]),
        #                      (skill_requirements["option 1"]["outcome_reference"][1], skill_requirements["option 1"]["outcome_args"])]
        "outcome_reference": skill_requirements["option 1"]["outcome_reference"],
        },
    }
    return exploit_system


remove_tool_from_system = {}


def get_deploy_tool(decision_struct, tool_details: dict, access_struct: dict, skill_requirements: dict ) -> dict:
    '''
    success and failure functons need to be called in both the play and target objects.
    !! I need to modify all of the success states to the [(,[]),(,[])] format for this functionality to work.
    '''
    implant_system = {
        "title": "Deploy tool to target.",
        "option 1" : {
        "definition" : "",
        "required skill values" : {
            "exploit development": 0,
            "network exploitation" : 1,
            "programming" : 0,
            "scripting": 1
            },
        "time cost": 2,
        # (# of dice sides, value to achieve success)
        "chance": (20, 5),
        # Redirector + 1
        #"success bonus": "",
        "bonus_chance": (0,0),
        "bonus_define": "None",
        "bonus_type": [],
        "bonus_reference": [],
        # Add 2 minutes to a hacker's encumbered timer.
        #"failure cost": "",
        "failure_state": False,
        "failure_define": "Increment hacker's burnout counter by one. Failures during exploit can happen for many reasons.",
        "failure_reference": [(decision_struct["context"].incrementBurnoutCounter,[])] + skill_requirements["option 1"]["failure_reference"],
        #"failure_message": [skill_requirements["option 1"]["failure_message"]],
        # outcome_reference is the function that is executed upon success.
        #"outcome_args": skill_requirements["option 1"]["outcome_args"],
        #"outcome_reference": [(skill_requirements["option 1"]["outcome_reference"][0], skill_requirements["option 1"]["outcome_args"]),
        #                      (skill_requirements["option 1"]["outcome_reference"][1], skill_requirements["option 1"]["outcome_args"])]
        "outcome_reference": skill_requirements["option 1"]["outcome_reference"],
        },
        } 

    return implant_system


def get_scan_system(decision_struct: dict, target_details: dict) -> dict:



    return dict

