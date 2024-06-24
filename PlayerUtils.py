from random import randrange, sample
from sys import _current_frames
from time import sleep
from copy import deepcopy
import string


from TargetUtils import most_common_client_reg_ports_nix, most_common_server_reg_ports_nix, most_common_client_reg_ports_win, most_common_server_reg_ports_win, most_common_reg_ports_rtr_fw, most_common_reg_ports_emb


tool_type_list = ["beaconing","triggerable","keylogger","worm","virus","trojan", "system_monitor", "rat"]
platform_type = ["windows","linux","router","firewall","embedded"]
# lateral can be described as an exploit for some homebrew software inside the target network.
# LPE's function can be used to successfully mitigate logging|EDR|Firewall etc. once a
#   OR LPE CAN BE USED TO DRASTICALLY LOWER DETECTION ROLL
exploit_sub_type_list = ["rce", "lpe", "lateral","credentials"]

# platform types as defined in targetUtils.targetSystem.determineTargeType()
# ex item {"name": str, "type": implant|keylogger|worm|etc, "platform_type":win|nix|rtr|emb, "burned":bool, "permissions": user|limited service|system|kernel}
#tool_list = []

# ex item {"name": str, "type":lpe|rce, "platform_type": win|nix|rtr|emb ,"burned":bool }
# type will be either tool or exploit
#exploit_list = []

# need to make these tuples so that I can have the plain text name for shorthand recognition on the cli
handle_list = ["test1","test2","test3","test4","test5","test6","test7","test8","test9","test10"]

class PlayerGenerator():
    def __init__(self, name):
        self.name = name
        self.programming = self._getSkillValue()
        self.scripting = self._getSkillValue()
        self.network_exploitation = self._getSkillValue()
        self.exploit_development = self._getSkillValue()
        self.personality_bonus = self._getSkillValue()
        self.tools = []
        self.exploits = []
        self.cape_sn_tracker = []
        self._generateInitialArsenal()
        self.encumbered_timer_seconds = 0
        
        self.burnout_counter = 0
        self.burnedout = False

        # This is a list of targets actively connected to
        # This dict is a singly linked list, linked in reverse.
        # target_connection_details = {
        #   "src": [target_name|rdr],
        #   "src_cape": "",
        #   "targeted_system": [target_name],
        #   "access_method": [exploit|rat|implant],
        #   "cape_sn" : "",
        #   "instance_id": 0,
        #   "src_instance_id":"",
        # }
        # in the case of an assisted connect, the source will be left empty
        # this can/will be checked to see if an adverse disconnect effects another actor on target.
        self.connected_targets = []
        # the Modification_Mutex will ultimately be used to prevent modificaiton collisions.  
        self.Modification_Mutex = False

    def _getSkillValue(self) -> int:
        return randrange(1,5)

    def _coinFlip(self) -> int:
        return randrange(0,1)

    def _rollD6(self) -> int:
        return randrange(1,6)

    def _rollD12(self) -> int:
        return randrange(1,12)

    def _rollD20(self) -> int:
        return randrange(1,20)

    def developCapability(self, capability_details: dict, permissions: str) -> None:
        # I don't know when the check/roll for success will occur.
        # name will be the capability serial number for cape uniqueness tracking
        
        capability = {
            "type": capability_details["cape_category"],
            "name": None,
            "sub_type": capability_details["cape_type"],
            "port": capability_details["port"],
            "platform_type": capability_details["platform"],
            "burned": capability_details["burned"],
            "permissions": permissions,
        }

        self.addCapabilityToInventory(capability)
        print()
        print(capability)
        print()
        return
        #return capability

    def tool_serial_number_generator(self) -> str:
        #s = string.ascii_lowercase+string.digits

        while True:
            #sn_name = ''.join(sample(s, 10))
            counter = 0
            sn_name = ""
            while counter <= 5:
                sn_name += str(randrange(0,9))
                counter += 1
            if sn_name not in self.cape_sn_tracker:
                return sn_name
            continue

    def add_cape_to_tracked_list(self, sn_name) -> None:
        self.cape_sn_tracker.append(sn_name)
        return
    
    def _generateInitialArsenal(self) -> None:
        ''' generate anywhere from 1-3 tools that the player/npc starts with. '''
        global tool_type_list
        global platform_type
        global exploit_sub_type_list

        num_of_capes = randrange(1,3)
        while num_of_capes > 0:
            instance_platform_type = platform_type[randrange(0, len(platform_type) - 1)]
            sub_type = ""
            capability_details = {
                "cape_category":"",
                "cape_type": "",
                "bonus_type": "",
                "platform": "",
                "port": None,
                "name": None,
                "burned": False,
                "permissions": "",
            }   

            if randrange(0,10) > 8:
                capability_details["burned"] = True

            permission = ""
            permission_selection = randrange(1,40)
            if (permission_selection >= 1) and (permission_selection <= 10):
                permission = "user"
            elif (permission_selection >= 11) and (permission_selection <= 20):
                permission = "limited service"
            elif (permission_selection >= 21) and (permission_selection <= 30):
                permission = "system"
            elif (permission_selection >= 31) and (permission_selection <= 40):
                permission = "kernel"
            else:
                print("[DEBUG] ERROR: Roll for permission has an invalid value")
                permission = "user"


            if randrange(0,10) > 5 :

                cape_type = "exploit"
                sub_type = exploit_sub_type_list[randrange(0, len(exploit_sub_type_list) - 1)]
                # Need to implement a check of a valid port number to assign an RCE with.
                port = None
                if sub_type == "rce":
                    if instance_platform_type == 'windows':
                        port_list = most_common_client_reg_ports_win + most_common_server_reg_ports_win
                        port_choice = randrange(0, len(port_list))
                        port = port_list[port_choice]

                    elif instance_platform_type == 'linux':
                        port_list = most_common_client_reg_ports_nix + most_common_server_reg_ports_nix
                        port_choice = randrange(0, len(port_list))
                        port = port_list[port_choice]

                    elif (instance_platform_type == 'router') or (instance_platform_type == 'firewall'):
                        port_list = most_common_reg_ports_rtr_fw
                        port_choice = randrange(0, len(port_list))
                        port = port_list[port_choice]

                    elif instance_platform_type == 'embedded':
                        port_list = most_common_reg_ports_emb
                        port_choice = randrange(0, len(port_list))
                        port = port_list[port_choice]

                    else:
                        pass
                elif sub_type == "lpe":
                    # I need to change the permissions to reflect the appropriate ones for an LPE
                    pass

                sn_name = self.tool_serial_number_generator()
                #self.add_cape_to_tracked_list(sn_name)

                #self.exploits.append(self.developCapability(cape_type=cape_type, 
                #                                          name=sn_name,
                #                                          sub_type=sub_type, port=port, 
                #                                          platform_type=instance_platform_type, 
                #                                          burned=burned))

                capability_details["cape_category"] = cape_type
                capability_details["cape_type"] = sub_type
                capability_details["platform"] = instance_platform_type
                if port != None:
                    capability_details["port"] = port

                self.developCapability(capability_details, permission)

            else:
                cape_type = "tool"
                sub_type = tool_type_list[randrange(0, len(tool_type_list) - 1)]
                sn_name = self.tool_serial_number_generator()
                #self.add_cape_to_tracked_list(sn_name)

                # if triggerable there needs to be some logic to open a port on the 
                # target system
                port = None
                if sub_type == "triggerable":
                    proto = randrange(0,1)
                    if proto == 0:
                        proto = "TCP"
                    else:
                        proto = "UDP"
                    port = (str(randrange(1,65535)), proto)

                capability_details["cape_category"] = cape_type
                capability_details["cape_type"] = sub_type
                capability_details["platform"] = instance_platform_type
                if port != None:
                    capability_details["port"] = port


                self.developCapability(capability_details, permission)
                #self.tools.append(self.developCapability(cape_type, 
                #                                         name=sn_name, 
                #                                         sub_type=sub_type, 
                #                                         platform_type=instance_platform_type, 
                #                                         burned=burned))




            num_of_capes -= 1

    def addCapabilityToInventory(self, capability):
        # recv cape_details, get a SN to assign to it, and save it to inventory.
        capability["name"] = self.tool_serial_number_generator()
        self.add_cape_to_tracked_list(capability["name"])
        if capability["type"] == "exploit":
            self.exploits.append(capability)
        elif capability["type"] == "tool":
            self.tools.append(capability)

        print(f"[DEBUG] added {capability}")
  
    def getTools(self) -> list:
        return self.tools 

    def getExploits(self) -> list:
        return self.exploits

    # this is a duplicate function.
    # It can be left and used to return a roll bonus or it can be ascertain in the team version 
    def getCapeSubtype(self, cape_sn: str) -> str:
        combined_cape_list = self.tools + self.exploits
        for cape in combined_cape_list:
            if cape['name'] == cape_sn:
                return cape['sub_type']
        return ""

    def getCapeBurnedStatus(self, cape_sn) -> bool:
        combined_cape_list = self.tools + self.exploits
        for cape in combined_cape_list:
            if cape['name'] == cape_sn:
                return cape["burned"]
        return False

    def incrementBurnoutCounter(self) -> None:
        self.burnout_counter += 1
        if self.burnout_counter > 15:
            # once this is triggered you cannot use this player anymore. 
            # It may be prudent to zero out the NPC's stats 
            self.burnedout = True
            self.programming = 0 
            self.scripting = 0
            self.network_exploitation = 0
            self.exploit_development = 0
            self.personality_bonus = 0
        return

    def decrementBurnoutCounter(self) -> None:
        if self.burnout_counter > 5:
            # once this is triggered you cannot use this player anymore. 
            # It may be prudent to zero out the NPC's stats 
            return
        self.burnout_counter = 0 
        return

    def getTaskingAcknowledgementResponse(self, response_Type):
        # need to check encumbered status and allow for non tasking communication responses.
        if response_Type == "idk":
            responses = ["What are you talking about?",
                         "Think, key, speak!",
                         "Dude...",
                         "..."
                ]
            return responses[randrange(0,len(responses) - 1)]
        
        elif response_Type == "blank_task":
            responses = ["I don't have time for games!",
                         "Yes... you need something?",
                         "Sup?",
                         "Let me know when you figure out what you want..",
                         "If you don't know what you want how am I supposed to figure it out?",
                ]
            return responses[randrange(0,len(responses) - 1)]

        elif response_Type == "which_one":
            responses = ["Which one?",
                         "umm.... Which one?",
                         "You need to tell me which one you\'re talking about...",
                         "I can\'t read your mind.",
                         "I guess you want me to choose???",
                ]
            return responses[randrange(0,len(responses) - 1)]

        elif response_Type == "not_valid":
            responses = ["umm.... What does that even mean?",
                         "What am I supposed to do with this?",
                         "???",
                ]
            return responses[randrange(0,len(responses) - 1)]

        elif response_Type == "encumbered":
            responses = ["I haven't finished the last thing you tasked me with.",
                         "I'm busy...",
                         "When I finish what I'm currently working on I\'ll hit you up.",
                         "Give me a minute.",
                ]
            return responses[randrange(0,len(responses) - 1)]

        elif response_Type == "failed":
            responses = ["ugh....",
                         "Give me some time to go study up on that and I'll take another crack at it.",
                         "... I'm going to get fired aren't I?",
                         "I hate computers.",
                ]
            return responses[randrange(0,len(responses) - 1)]

        elif response_Type == "burnedout":
            responses = ["I'm done...",
                         "I quit.",
                         "There's no wins to be had here, I'm out.",
                         "I'm off the team and am working on my departure paperwork.",
                         "I'm so burned out. I'm sick of this palce.",
                ]
            return responses[randrange(0,len(responses) - 1)]

        elif response_Type == "win":
            responses = ["Nothing like a win to lift the spirits",
                         "I can't stop now, gotta keep winning",
                         "What's next I'm on a roll.",
                         "Let's make quick work of this network so we can get paid.",
                         "Too easy!",
                ]
            return responses[randrange(0,len(responses) - 1)]

        elif response_Type == "cannot exploit":
            responses = ["I can't exploit that...",
                ]
            return responses[randrange(0,len(responses) - 1)]

        elif response_Type == "bad_exploit_source":
            responses = ["I don't have access to that pivot box...",
                         "I would need to exploit that pivot system first.",
                         "I have to come from somewhere else, we don't have access to that pivot box...",
                ]
            return responses[randrange(0,len(responses) - 1)]



        else:
            return ("[!] ERROR: You called a non-existant response_type.")

        '''
        if attitude == "spicy":
            pass
        elif attitude == "frustrated":
            pass
        elif attitude == "angry":
            pass
        elif attitude == "excited":
            pass
        elif attitude == "happy":
            pass
        elif attitude == "indifferent":
            pass
        '''

    def recvdTaskBonus(self, skill: str) -> None:
        if skill == "programming":
            self.programming += 1
        elif skill == "scripting":
            self.scripting += 1
        elif skill == "network_exploitation":
            self.network_exploitation += 1
        elif skill == "exploit_development":
            self.exploit_development += 1
        elif skill == "personality_bonus":
            self.personality_bonus += 1            
        else:
            print(f"[!] ERROR: {skill} is not a valid value to be passed to the recvdTaskBonus method.")
            return

        if self._rollD20() >= 10:
            self.decrementBurnoutCounter()
            #print(f"[*] Congratulation! {self.name} is in better spirites and isn't as close to burning out!")
            self.getTaskingAcknowledgementResponse("win")

        return

    def _message_emptyEndOfTaskMessage(self) -> dict:
        message = {
            "name" : self.name,
            "task_type": "",
            "success": True,
            "cost": [],
            "bonus": [],
            "narrative":"",
        } 
        return message

    # need to change to _cape_BurnCape()
    def _cape_BurnExploit(self, cape_sn: str) -> None:
        for index, exploit in enumerate(self.exploits):
            if exploit["name"] == cape_sn:
                self.exploits[index]["burned"] = True

    def _cape_GetCapeSnFromInstanceId(self, instance_id: str) -> str:
        for cape in self.connected_targets:
            if cape['instance_id'] == instance_id:
                return cape['cape_sn']
        return ""

    def _cape_CheckForInstancesFromCapeSn(self, cape_sn: str, targeted_system:str) -> list:
        for connection in self.connected_targets:
            if (connection['cape_sn'] == cape_sn) and (connection['targeted_system'] == targeted_system):
                return connection['instance_id']
        return ""

    def _access_GenereateAccessInstanceID(self) -> str:
        access_instance_id = ""
        while True:
            access_instance_id = self.tool_serial_number_generator()
            if self._access_ValidateUniquenessOfGeneratedInstanceID(access_instance_id):
                break
        return access_instance_id

    def _access_ValidateUniquenessOfGeneratedInstanceID(self, access_instance_id: str) -> bool:
        for connection in self.connected_targets:
            if connection['instance_id'] == access_instance_id:
                return False
        return True
    
    # The 1st real argument is present so that the outcome call can be the same for both the 
    # hacker object and the target object that both need similar work done on them.
    def _access_ConnectToTarget(self, target_connection_details: dict) -> str:
        '''
        target_connection_details = {
            "src": [target_name|rdr],
            "src_cape": "",
            "targeted_system": [target_name],
            "access_method": [exploit|rat|implant],
            "cape_sn" : "",
            # The instance ID is stapled on at the end before adding the connection to target
            "instance_id": "0",
            "src_instance_id:"0",
        }
        '''
        #if "instance_id" not in target_connection_details:
        if target_connection_details["instance_id"] == "":
            #instance_id = self._access_GenereateAccessInstanceID()
            target_connection_details["instance_id"] = self._access_GenereateAccessInstanceID()
            #target_connection_details = { **target_connection_details, **{'instance_id': instance_id}}

        self.connected_targets.append(target_connection_details)
        return target_connection_details['instance_id']

    def _access_DisconnectFromTarget_SinglePlayer(self, target_name: str, instance_id: str) -> list:
        # change to systems_disconnected = [[target_name, cape_sn],[]]
        systems_disconnected = []
        for index, access in enumerate(self.connected_targets):
            if ((access["targeted_system"] == target_name) and (access['instance_id'] == instance_id)) or (access['src_instance_id'] == [instance_id]):
                systems_disconnected.append(access)
                self.connected_targets.pop(index)

        upstream_disconnected_systems = self._access_DisconnectFromUpstreamSystems_SinglePlayer(target_name, instance_id)
        total_disconnected_targets = systems_disconnected + upstream_disconnected_systems
        print(f"[DEBUG] {len(total_disconnected_targets)} targets were disconnected associated with {self.name}.")
        #This function will retrun a list that needs to be passed to the TargetNetwork Object for the proper modifications.
        return total_disconnected_targets

    def _access_DisconnectFromUpstreamSystems_SinglePlayer(self, target_name: str, instance_id: str) -> list:
        
        systems_disconnected = []
        current_wave = [target_name]
        next_wave = []
        src_instance_id = [instance_id]
        while True:
            for index_1, source_system in enumerate(current_wave):
                for index_2, access in enumerate(self.connected_targets):

                    # I think the logic bug is here. The src_instance_id is equal to "" and is being allowed to pass.
                    # this is allowing rats sriced from an exploit from a rdr to get disconnected too.

                    if (access["src"] == source_system) and ((src_instance_id == access["src_instance_id"]) or (src_instance_id == "")):
                        source_system = access["targeted_system"]
                        src_instance_id = access['instance_id']
                        systems_disconnected.append(access)
                        next_wave.append(access['targeted_system'])
                        self.connected_targets.pop(index_2)
                if len(next_wave) == 0:
                    break
            if next_wave == []:
                break
            current_wave = deepcopy(next_wave)
            next_wave = []

        return systems_disconnected
 
    def _access_HasAccessToTarget(self, target_name: str) -> bool:
        for target in self.connected_targets:
            if target["targeted_system"] == target_name:
                return True
        return False

    def _access_ModifyAccessDetails(self, access_struct) -> bool:
        # need to do a check to see if RAT or implant is already present
        # if so the connected_target entry needs to be duplicated to track a second connection to the target
        for target in self.connected_targets:
            if target["targeted_system"] == access_struct["target_name"]:
                if (target["access_method"] == 'exploit') and (access_struct['access_method'] == 'rat'):
                    target["access_method"] = access_struct["access_method"]
                    target["cape_sn"] = access_struct["cape_sn"]
                    return True
                elif (target["access_method"] == 'rat') and (access_struct['access_method'] == 'rat'):
                    self._access_ConnectToTarget(access_struct['target_connection_details'])
                    return True
                elif (target["access_method"] == 'implant') or (target["access_method"] == 'triggerable') or (target["access_method"] == 'beaconing'):
                    target["access_method"] = access_struct["access_method"]
                    target["cape_sn"] = access_struct["cape_sn"]
                    return True
        return False


class hackingTeam():
    def __init__(self, player, npc1, npc2, npc3):
        self.player = player
        self.npc1 = npc1
        self.npc2 = npc2
        self.npc3 = npc3
        
        # I don't think these update after the original populate
        # I think I replace these with a method that returns a team wide cape inventory when called
        self.tool_list = []
        self._getInitialToolList()
        self.exploit_list = []
        self._getInitialExploitList()

        self.redirectors = self._getStartingRedirectorCount()

        self.message_queue = []
    
    def _getInitialExploitList(self) -> None:

        npcs = [self.npc1,self.npc2,self.npc3, self.player]
        for npc in npcs:
            for exploit in npc.exploits:
                self.exploit_list.append(exploit)

        return

    def _getInitialToolList(self) -> None:
        npcs = [self.npc1,self.npc2,self.npc3, self.player]
        for npc in npcs:
            for tool in npc.tools:
                self.tool_list.append(tool)
                
        return

    def addExploitToTeamList(self, exploit) -> None:
        self.exploit_list.append(exploit)
        return

    def addToolToTeamList(self, tool) -> None:
        self.tool_list.append(tool)
        return

    def getTeamList(self) -> list:
        return [self.player, self.npc1, self.npc2, self.npc3]

    def _getStartingRedirectorCount(self) -> int:
        return randrange(0,3)

    def increment_redirector(self) -> None:
        self.redirectors += 1
        return

    # this will need to take TargetNetwork as an arg 
    def decrement_redirectors(self) -> None:
        if self.redirectors > 1:
            self.redirectors -= 1
        elif self.redirectors == 1:
            self.redirectors -= 1
            # This will eventually go through the target network and remove all beaconing implants.
        else:
            print(f"[ERROR] Attempted to subtract 1 from a redirector count of 0.")

    def _values_toolDevelopmentDecision(self, sub_type: str) -> dict:
        ''' This is passed to the det_devlop_capability() to populate the decision values.'''
        permission_levels = ["user","limited service","system","kerenel"]

        skill_requirements = {
            "option 1": {
                "required skill values" : {
                    "exploit development": 0,
                    "network exploitation" : 1,
                    "programming" : 0,
                    "scripting": 1
                    },
                "time cost": 2,
                "bonus_define": "",
                "bonus_type": [],
                "outcome_args": permission_levels[0],
                },
            "option 2": {
                "required skill values" : {
                    "exploit development": 0,
                    "network exploitation" : 1,
                    "programming" : 0,
                    "scripting": 1
                    },
                "time cost": 2,
                "bonus_define": "",
                "bonus_type": ["programming"],
                "outcome_args": permission_levels[1],
                },
            "option 3": {
                "required skill values" : {
                    "exploit development": 0,
                    "network exploitation" : 1,
                    "programming" : 0,
                    "scripting": 1
                    },
                "time cost": 2,
                "bonus_define": "",
                "bonus_type": ["programming","scripting"],
                "outcome_args": permission_levels[2],
                },
            "option 4": {
                "required skill values" : {
                    "exploit development": 0,
                    "network exploitation" : 1,
                    "programming" : 0,
                    "scripting": 1
                    },
                "time cost": 2,
                "bonus_define": "",
                "bonus_type": ["programming","scripting","personality_bonus"],
                "outcome_args": permission_levels[3],
                }
            }
        return skill_requirements

    def _values_exploitDevelopmentDecision(self, sub_type: str) -> dict:
        ''' This is passed to the det_devlop_capability() to populate the decision values.'''
        permission_levels = ["user","limited service","system","kerenel"]
        if sub_type == "lpe":
            permission_levels = ["system","kernel","vm break-in", "vm break-out"]

        skill_requirements = {
            "option 1": {
                "required skill values" : {
                    "exploit development": 0,
                    "network exploitation" : 1,
                    "programming" : 0,
                    "scripting": 1
                    },
                "time cost": 2,
                "bonus_define": "",
                "bonus_type": [],
                "outcome_args": permission_levels[0],
                },
            "option 2": {
                "required skill values" : {
                    "exploit development": 0,
                    "network exploitation" : 1,
                    "programming" : 0,
                    "scripting": 1
                    },
                "time cost": 2,
                "bonus_define": "",
                "bonus_type": ["exploit_development"],
                "outcome_args": permission_levels[1],

                },
            "option 3": {
                "required skill values" : {
                    "exploit development": 0,
                    "network exploitation" : 1,
                    "programming" : 0,
                    "scripting": 1
                    },
                "time cost": 2,
                "bonus_define": "",
                "bonus_type": ["exploit_development","scripting"],
                "outcome_args": permission_levels[2],
                },
            "option 4": {
                "required skill values" : {
                    "exploit development": 0,
                    "network exploitation" : 1,
                    "programming" : 0,
                    "scripting": 1
                    },
                "time cost": 2,
                "bonus_define": "",
                "bonus_type": ["exploit_development","scripting","personality_bonus"],
                "outcome_args": permission_levels[3],
                }
            }
        return skill_requirements

    def _values_ExploitTargetDecision(self, exploit_details: dict, decision_struct: dict) -> dict:
        cape_details = {
            "type" : "exploit",
            "subtype" : exploit_details['subtype'],
            "cape_sn" : exploit_details["exploit_sn"],
            "burned" : decision_struct["context"].getCapeBurnedStatus(exploit_details["exploit_sn"]),
            "permissions" : exploit_details["permissions"],
            "currently_present" : True,
            "instance_id" : [exploit_details['instance_id'],],
            "src_instance_id": exploit_details["src_instance_id"],
            }

        # Narrative type needs to be determined along side of the rolled failure consequnces.
        failure_result_details = {
            "cape": cape_details,
            "was_burned": False,
            "now_burned": False,
            "lose_pivot_system": False,
            "enable_firewall": False,
            "was_edr_enabled": False,
            "enable_edr": False,
            }

        if decision_struct["context"].getCapeBurnedStatus(exploit_details["exploit_sn"]):
            # Burned status is not set because this branch ascertained it's already burned
            # the rolls in this branch have a more likely chance of severe consequences.
            # 1. roll to see if you lose access to the from exploit_details["source_system"]
            if not decision_struct["TargetSystem"].EDR:
                if decision_struct["context"]._rollD20() >= 13:
                    failure_result_details["lose_pivot_system"] = True
                # 2. roll to have the administrator turn on the firewall to target system
                if not decision_struct["TargetSystem"].FirewallEnabled:
                    if decision_struct["context"]._rollD20() >= 12:
                        failure_result_details["enable_firewall"] = True
                # 3. roll to have the administrator install an EDR on the tarted system 
                if decision_struct["context"]._rollD20() >= 14:
                    failure_result_details["enable_edr"] = True

            else:
                if decision_struct["context"]._rollD20() >= 0:
                    failure_result_details["lose_pivot_system"] = True
        else:
            if not decision_struct["TargetSystem"].EDR:
                # 1. roll to burn the exploit
                if decision_struct["context"]._rollD20() >= 17:
                    failure_result_details["now_burned"] = True
                # 2. roll to see if you lose access to the from exploit_details["source_system"]
                if decision_struct["context"]._rollD20() >= 15:
                    failure_result_details["lose_pivot_system"] = True
                # 3. roll to have the administrator turn on the firewall to target system
                if not decision_struct["TargetSystem"].FirewallEnabled:
                    if decision_struct["context"]._rollD20() >= 12:
                        failure_result_details["enable_firewall"] = True
                # 3. roll to have the administrator install an EDR on the tarted system 
                if decision_struct["context"]._rollD20() >= 14:
                    failure_result_details["enable_edr"] = True

            else:
                if decision_struct["context"]._rollD20() >= 14:
                    failure_result_details["now_burned"] = True
                if decision_struct["context"]._rollD20() >= 12:
                    failure_result_details["lose_pivot_system"] = True

        failure_message = decision_struct["targetNetwork"]._access_NarrativeCapeFailureCause(failure_result_details)
        '''
        target_connection_details = {
            "src": [target_name|rdr],
            "targeted_system": [target_name],
            "access_method": [exploit|rat|implant],
        }
        '''
        # target name is validated prior to the call to this function. 
        target_connection_details = {
            "src" : exploit_details["source_system"],
            "src_cape" : exploit_details["src_cape"],
            "targeted_system" : exploit_details['target'],
            "access_method" : "exploit",
            "cape_sn": cape_details["cape_sn"],
            "instance_id" : exploit_details['instance_id'],
            "src_instance_id": exploit_details["src_instance_id"],
            }

        if exploit_details["author_is_context"]:
            skill_requirements = {
                "option 1": {
                    "definition":"Utilize exploit against target. (as exploit author)",
                    "required skill values" : {
                        "exploit development": 0,
                        "network exploitation" : 1,
                        "programming" : 0,
                        "scripting": 1
                        },
                    "time cost": 2,
                    "chance": (0,0),
                    "bonus_define": "",
                    "bonus_type": [],
                    "failure_define": "",
                    "failure_reference": [(decision_struct['TargetSystem']._exploit_ExploitThrowFailure, [failure_result_details])],
                    "failure_message": failure_message,
                    #"outcome_args": [cape_details, target_connection_details],
                    #"outcome_reference": [decision_struct["TargetSystem"]._access_ConnectToTarget, decision_struct["context"]._access_ConnectToTarget],
                    "outcome_reference":[(decision_struct["TargetSystem"]._access_ConnectToTarget,[cape_details]),(decision_struct["context"]._access_ConnectToTarget,[target_connection_details])]
                    },
            }
            return skill_requirements
        else:
            skill_requirements = {
                "option 1": {
                    "definition":"Utilize exploit against target. (owned by another hacker)",
                    "required skill values" : {
                        "exploit development": 0,
                        "network exploitation" : 1,
                        "programming" : 0,
                        "scripting": 1
                        },
                    "time cost": 2,
                    "chance": (0,0),
                    "bonus_define": "",
                    "bonus_type": [],
                    "failure_define": "",
                    "failure_reference": [(decision_struct['TargetSystem']._exploit_ExploitThrowFailure, [failure_result_details])],
                    "failure_message": failure_message,
                    #"outcome_args": [cape_details, target_connection_details],
                    #"outcome_reference": [decision_struct["TargetSystem"]._access_ConnectToTarget, decision_struct["context"]._access_ConnectToTarget],
                    "outcome_reference":[(decision_struct["TargetSystem"]._access_ConnectToTarget,[cape_details]),(decision_struct["context"]._access_ConnectToTarget,[target_connection_details])]

                    },
            }
            return skill_requirements

    def _values_GetTeamMemberReference(self, context_name: str) -> object:
        characters =  [self.player, self.npc1, self.npc2, self.npc3]
        for character in characters:
            if character.name == context_name:
                return character
        print("[DEBUG] ERROR context_name not found in hacker list.")
        return object()

    def _values_DeployToolDecision(self, access_struct:dict, tool_details: dict, decision_struct: dict) -> dict:


        if tool_details["author_is_context"]:
            skill_requirements = {
                "option 1": {
                    "definition":"Upload and execute tool to target. (as the capability author)",
                    "required skill values" : {
                        "exploit development": 0,
                        "network exploitation" : 1,
                        "programming" : 0,
                        "scripting": 1
                        },
                    "time cost": 2,
                    "chance": (0,0),
                    "bonus_define": "",
                    "bonus_type": [],
                    "failure_define": "",
                    "failure_reference": [(decision_struct['TargetSystem']._upload_DeployToolToTarget_Failure, [tool_details])],
                    "outcome_reference": [(decision_struct["TargetSystem"]._upload_DeployToolToTarget_Success, [tool_details]),
                                          (decision_struct["HackingTeam"]._upload_DeployToolToTarget_Success,[access_struct,tool_details,decision_struct])]
                    },
            }
            return skill_requirements
        else:
            skill_requirements = {
                "option 1": {
                    "definition":"Upload and execute tool to target. (not as the author of the capability)",
                    "required skill values" : {
                        "exploit development": 0,
                        "network exploitation" : 1,
                        "programming" : 0,
                        "scripting": 1
                        },
                    "time cost": 2,
                    "chance": (0,0),
                    "bonus_define": "",
                    "bonus_type": [],
                    "failure_define": "",
                    "failure_reference": [(decision_struct['TargetSystem']._upload_DeployToolToTarget_Failure, [tool_details])],
                    "outcome_reference": [(decision_struct["TargetSystem"]._upload_DeployToolToTarget_Success, [tool_details]),
                                          (decision_struct["HackingTeam"]._upload_DeployToolToTarget_Success,[access_struct,tool_details,decision_struct])]

                    },
            }
            return skill_requirements

    def _message_addMessageToQueue(self, message) -> None:
        self.message_queue.append(message)
        return

    def _message_getMessageFromQueue(self) -> dict:
        message = self.message_queue[0]
        self.message_queue.pop(0)
        return message

    def _message_getNumberOfMessages(self) -> int:
        return len(self.message_queue)

    def _message_emptyMessageQueue(self) -> None:
        self.message_queue = []
        return

    def _cape_validateCapeSn(self, cape_sn) -> bool:
        characters =  [self.player, self.npc1, self.npc2, self.npc3]
        for character in characters:
            cape_list = character.tools + character.exploits            
            for cape in cape_list:
                if cape_sn == cape['name']:
                    return True        
        return False

    def _cape_getCapePort(self, cape_sn: str) -> int:
        characters = [self.player, self.npc1, self.npc2, self.npc3]
        for character in characters:
            if cape_sn in character.cape_sn_tracker:
                print(f"[DEBUG] cape_sn in cape_sn_tracker.")
                for cape in character.tools + character.exploits:
                    if cape_sn == cape["name"]:
                        print(f"[DEBUG] cape_sn in cape_sn_tracker.")
                        if cape['port'] != None:
                            return cape['port']
                        else:
                            return 0
        return 0

    def _cape_GetCapeOwner(self, cape_sn: str) -> str:
        # This code needs to be changed to be like every other similar function
        characters =  [self.player, self.npc1, self.npc2, self.npc3]
        for character in characters:
            for tool in character.getTools():
                if tool["name"] == cape_sn:
                    return character.name
            for exploit in character.getExploits():
                if exploit["name"] == cape_sn:
                    return character.name
        return ""

    def _cape_GetCapePermissions(self, cape_sn: str) -> str:
        characters =  [self.player, self.npc1, self.npc2, self.npc3]
        #permission_levels = ["user","limited service","system","kernel"]
        for character in characters:
            combined_cape_list = character.tools + character.exploits
            for cape in combined_cape_list:
                if cape['name'] == cape_sn:
                    return cape['permissions']
                    #for index, permission in enumerate(permission_levels):
                        #if cape['permissions'] == permission:
                            #return (cape['permissions'],index)
                            
        return ""

    def _cape_GetCapeSubtype(self, cape_sn: str) -> str:
        characters =  [self.player, self.npc1, self.npc2, self.npc3]
        for character in characters:
            combined_cape_list = character.tools + character.exploits
            for cape in combined_cape_list:
                if cape['name'] == cape_sn:
                    return cape['sub_type']
        return ""

    def _cape_CheckForInstancesFromCapeSn(self, cape_sn: str, targeted_system: str) -> str:
        characters =  [self.player, self.npc1, self.npc2, self.npc3]
        for character in characters:
            instance_id = character._cape_CheckForInstancesFromCapeSn(cape_sn, targeted_system)
            if instance_id != "":
                return instance_id
        return ""

    def _cape_GetCapePlatformType(self, cape_sn: str) -> str:
        characters =  [self.player, self.npc1, self.npc2, self.npc3]
        for character in characters:
            combined_cape_list = character.tools + character.exploits
            for cape in combined_cape_list:
                if cape['name'] == cape_sn:
                    return cape['platform_type']
        return ""



    def _cape_BurnCape(self, cape_sn: str) -> None:
        pass

    def _cape_GetCapeBurnedStatus(self, cape_sn: str) -> bool:
        characters = [self.player, self.npc1, self.npc2, self.npc3]
        burned = False
        for character in characters:
            burned = character.getCapeBurnedStatus(cape_sn)
            if burned == True:
                return burned
        return burned

    def _upload_DeployToolToTarget_Success(self, access_struct: dict, tool_details: dict, decision_struct: dict) -> None:

        # THIS MAY NEED A REDEFINITION BECAUSE IT'S NOT ONLY FOR TOOLS IT'S ALSO FOR ACCESS CAPABILITIES.

        '''
        access_struct = {
            "context_name" :  decision_struct["context"].name,
            "target_name" : decision_struct['TargetSystem'].name,
            "access_method" : "",
            "cape_sn" : "",

            }
        '''
        if (tool_details["subtype"] == "rat"):
            access_struct["access_method"] = "rat"
        elif (tool_details["subtype"] == "beaconing"):
            access_struct["access_method"] = "implant"
        elif (tool_details["subtype"] == "triggerable"):
            access_struct["access_method"] = "implant"
            # need to modify the target object to reflect the new need for an open port
        else:
            print("[DEBUG] ERROR: invalid cape type for access method articualtion.")
            print("[DEBUG] THIS IS WHERE THE DEPLOYMENT OF ATTACK PAYLOADS AND OTHER TOOLS WILL BE IMPLEMENTED.")
            return

        tool_details["type"] = "tool"


        context = self._values_GetTeamMemberReference(access_struct["context_name"])
        # this check may need to remain for testing purposes, but notification to the user be removed
        # because a normal execution state could result in this error message.
        if not context._access_ModifyAccessDetails(access_struct):
            print("[DEBUG] ERROR: Failed to modify the state or can't locate the target in the player's access list.")
            return



        return

    def _upload_DeployToolToTarget_Failure(self, access_struct: dict, tool_details: dict, decision_struct: dict) -> bool:
        # Unlike the exploit failure state, which is determined before exec,
        #   The implant failure state is determmined after the failure state is reached.
        # roll for which adverse effect occurs
        roll_result1 = decision_struct["context"]._rollD12()
        roll_result2 = decision_struct["context"]._rollD12()
        roll_results = roll_result1 + roll_result2

        #######
        # FROM WITHIN HERE IT WILL BE DETERMEINED WHICH DISCONNECT METHODS WILL BE UTILIZED
        # 1. The call to disconnect will return a list of targets that are being disconnected from.
        # 2. That list will be returned and a new structure will be constructed with the proper tool details
        #   to only effect the capabilities 
        # 3. depending on the disconnect type the TargetNetwork._access_DisconnectFromTarget_General() will
        #   go through a modify only the applicable targets. 
        #   - That means that the _access_DisconnectFromUpstreamSystems_AllPlayers() and
        #       _access_DisconnectFromUpstreamSystems_SinglePlayer() will be called and then the disconnect_struct
        #       will be constructed then passed to the TargetNetwork._access_DisconnectFromTarget_General()
        # 
        '''
        disconnect_struct = {
            "tool_details" : tool_details, # specifically for the tool_sn, but I may need it for more of the details.
            "affected_target" : access_struct["target_name"],
            "severity": <system|tool|instance>,
            # Instance: if there are more than 1 instance of a tool on that target it will only effect that instance
            # Tool: all instances of that tool are removed from the system
            # System: implants remain present on the system, RATs and other tools are removed from the system. all connectivitiy is lost.
            "reverse_depth": int(), # this will be how many systems in reverse get burned in the event of a high severity detection.
            "upstream_disconnects": list(),
        }
        '''
        # - There needs to be a logical path that reflects a tool deployment failure that is not a tool that requires connectivity. 
        #
        #######
        failure_struct = {
            "tool_details": tool_details,
            "affected_target": access_struct["target_name"],
            "severity": "",
            "connectivity" : None,
            }

        if (tool_details["subtype"] == "beaconing") or (tool_details["subtype"] == "triggerable") or (tool_details["subtype"] == "rat"):
            disconnect_struct = {
                "reverse_depth": 0,
                "upstream_disconnects": [], # this will call the appropriate level of target disconnect function(s)
                }
            failure_struct["connectivity"] = disconnect_struct


        if (roll_results >= 0) and (roll_results <= 4):
            print(f"[DEBUG] Tool deployment fail roll_results were {roll_results}.")
            # 1. Crash the system (due to preexiting system instability)
            #   - Add the cape to the list of capes, but disconnect the 

        elif (roll_results >= 5) and (roll_results <= 9):
            print(f"[DEBUG] Tool deployment fail roll_results were {roll_results}.")
            # 2. Crash the host process and lose connectivity (Unknown local thread injection failure w/i exploited process)
            #   - roll for detection, higher if EDR, but still high due to the fact that the system crashed
        elif (roll_results >= 10) and (roll_results <= 14):
            print(f"[DEBUG] Tool deployment fail roll_results were {roll_results}.")
            # 3. Crash another process (injection)
            #   - implant failed but access was not lost.
            #   - roll for detection if EDR increase chance
        elif (roll_results >= 15) and (roll_results <= 19):
            print(f"[DEBUG] Tool deployment fail roll_results were {roll_results}.")
            # 4. Upload succeded, but tool is not properly functioning (incorrect arch deployed)
            #   - potential CPU spiking or memory leak on target system led to administrator investigation
            #   - roll for chance for EDR enabling or detection and/or tool burning.
        elif (roll_results >= 20) and (roll_results <= 24):
            print(f"[DEBUG] Tool deployment fail roll_results were {roll_results}.")
            # 5. Tool executed, but is in a hung state. need to re-attempt and then terminate stuck cape.
            #   - no adverse effect.
        else:
            print(f"[DEBUG] ERROR roll_results value ({roll_results}) is invalid ")
            return False

        return True

    # the reterned int is how many targets that were ultimately disconnected by this call
    def _access_DisconnectFromTarget_AllPlayers(self, target_name: str, instance_id: str) -> list:
        ''' This would be called instead of the *_SinglePlayer method when a target system is rebooted/crashes '''
        


        #!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        # there needs to be some tracking between loops that will allow for the tracking of multi-layer redirection
        # Otherwise 3rd layer redirection of another actor will fail and will leave them connected despite all of their
        # redirection having been taken down.
        #!!!!!!!!!!!!!!!END!!!!!!!!!!!!!!!!

        downstream_instances = [instance_id]

        systems_disconnected = []
        characters =  [self.player, self.npc1, self.npc2, self.npc3]
        while downstream_instances != []:
            for character in characters:
                for index, instance in enumerate(downstream_instances):
                    #upstream_disconnected_systems = character._access_DisconnectFromTarget_SinglePlayer(target_name, instance_id)
                    upstream_disconnected_systems = character._access_DisconnectFromTarget_SinglePlayer(target_name, instance)
                    for system in upstream_disconnected_systems:
                        downstream_instances.append(system['instance_id'])
                    systems_disconnected = systems_disconnected + upstream_disconnected_systems
            _ = downstream_instances.pop(0)


            '''
            for index, access in enumerate(character.connected_targets):
                if (access["targeted_system"] == target_name): 
                    systems_disconnected.append(access)
                    character.connected_targets.pop(index)
            '''
        #upstream_disconnected_systems = self._access_DisconnectFromUpstreamSystems_AllPlayers(target_name)
        #total_disconnected_targets = systems_disconnected + upstream_disconnected_systems
        total_disconnected_targets = systems_disconnected
        print(f"[DEBUG] {len(total_disconnected_targets)} targets were disconnected across the entire team.")
        # this method returns a list that needs to be passed to the TargetNetwork Object
        #   so that the requisit targets can be modified.
        return total_disconnected_targets
        

    def _access_DisconnectFromUpstreamSystems_AllPlayers(self, target_name: str) -> list:
        ''' will go through all hackers and disconnect upstream systems. '''

        # I don't think this will do more than 1 leve above the initially disconnected system
        # There has to be a list generated each itteration so that each next system
        # up the stream can get looped through for upstream systems.
        '''
        systems_disconnected = []
        characters =  [self.player, self.npc1, self.npc2, self.npc3]
        for character in characters:
            source_system = target_name
            while True:
                detected = False
                for index, access in enumerate(character.connected_targets):
                    if access["src"] == source_system:
                        source_system = access["targeted_system"]
                        detected = True
                        systems_disconnected.append(access)
                        character.connected_targets.pop(index)
                if detected == False:
                    break
        return systems_disconnected
        '''
        '''
        systems_disconnected = []
        characters =  [self.player, self.npc1, self.npc2, self.npc3]
        for character in characters:
            #source_system = target_name
            current_wave = [target_name]
            next_wave = []
            while True:
                for index_1, source_system in enumerate(current_wave):
                    for index_2, access in enumerate(character.connected_targets):
                        if access["src"] == source_system:
                            source_system = access["targeted_system"]
                            systems_disconnected.append(access)
                            next_wave.append(access['targeted_system'])
                            character.connected_targets.pop(index_2)
                    if len(next_wave) == 0:
                        break
                current_wave = deepcopy(next_wave)
                next_wave = []

        return systems_disconnected
        '''








def backgroundTaskWorker(context, HackingTeam ,final_decision_struct) -> None:
    ''' background worker for encumbered players/NPCs '''
    print(f"[DEBUG] Inside background task worker thread.")
    context.encumbered_timer_seconds = final_decision_struct["time cost"]
    print(f"final_decision_struct['time cost']: {final_decision_struct['time cost']}")
    while context.encumbered_timer_seconds > 1:
        sleep(1)
        context.encumbered_timer_seconds -= 1
        print(f"[ ] {context.encumbered_timer_seconds} second(s) remaining for {context.name}.")

    task_message = context._message_emptyEndOfTaskMessage()
    task_message["task_type"] = final_decision_struct["title"]


    if final_decision_struct["failure_state"] == True:
        # I need to add a pull for the specific failure definition for the message generated
        for consequence in final_decision_struct["failure_reference"]:
            if consequence[1] == []:
                consequence[0]()
            else:
                #for types in consequence[1]:
                consequence[0](consequence[1])
        
        #for consequence in final_decision_struct["failure_reference"]:
        #    if final_decision_struct["failure_args"] == []:
        #        consequence()
        #    else:
        #        consequence(final_decision_struct["failure_args"][0])
        #        _ = final_decision_struct["failure_args"].pop(0)

        context.encumbered_timer_seconds = 0
        task_message["success"] = False
        task_message["cost"].append(final_decision_struct["failure_define"])
        # if type exploit or implant grab message from final_decision_struct['failure_message']
        HackingTeam._message_addMessageToQueue(task_message)
        return


    # rewrite this simiar to the failure state so that the decision dict can be modified to look the same.
    '''
    if len(final_decision_struct["outcome_args"]) > 0:
        for index, outcome in enumerate(final_decision_struct["outcome_reference"]):
            if index > len(final_decision_struct["outcome_args"]):
                results = outcome()
                if (results != None) and (results != "") and (results != []):
                    for item in results:
                        print(item)
            else:
                results = outcome(final_decision_struct["outcome_args"][index])
                if (results != None) and (results != "") and (results != []):
                    for item in results:
                        print(item)

    else:
        for outcome in final_decision_struct["outcome_reference"]:
            results = outcome()
            if (results != None) and (results != "") and (results != []):
                for item in results:
                    print(item)

    '''
    # New success outcome code segment start


    for outcome in final_decision_struct["outcome_reference"]:
        if outcome[1] == []:
            outcome[0]()
        else:

            # I think I'm overthinking this.
            if type(outcome[1]) == list:
                outcome[0](*outcome[1])
            else:
                outcome[0](outcome[1])

            #outcome[0](outcome[1])

    # New success outcome code segment end

    if final_decision_struct["bonus_chance"] != (0,0):
        if final_decision_struct["bonus_chance"][1] >= final_decision_struct["bonus_chance"][0]:
            # I think this will crash when there are bonus calls witohut a bonus type in bonus_type
            for index, bonus in enumerate(final_decision_struct["bonus_reference"]):
                if final_decision_struct["bonus_type"] == []:
                    bonus()
                else:
                    bonus(final_decision_struct["bonus_type"][index])
                    print(f"[*] Congratulations {context.name}, has been awarded an additional {final_decision_struct['bonus_type'][index]} skill point.")
                task_message["bonus"].append(final_decision_struct["bonus_define"])

    HackingTeam._message_addMessageToQueue(task_message)

    context.encumbered_timer_seconds = 0
    return

