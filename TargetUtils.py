from math import e, trunc
from random import randrange, shuffle
from copy import deepcopy



# Network links are mapped out in layers. targets in the same layer can talk to each other
# edge nodes are layer 1. Routers can traverse multiple layers.


# GLOBAL VARIABLES FOR BOTH INTER AND INTRA MODULE USAGE
most_common_client_reg_ports_nix = [(22,"TCP")]
most_common_server_reg_ports_nix = [(80,"TCP"),(443,"TCP"),(22,"TCP"),(21,"TCP"),
                                    (23,"TCP"),(25,"TCP"),(69,"TCP"),(110,"TCP"), 
                                    (123,"TCP"),(514,"UDP"),(8008,"TCP")]
most_common_client_reg_ports_win = [(135,"TCP"),(137,"UDP"),(137,"TCP"),(138,"UDP"),(139,"TCP"),
                                    (445,"TCP"),(3389,"TCP")]
most_common_server_reg_ports_win = [(80,"TCP"),(443,"TCP"),(8080,"TCP"),(53,"UDP"),(1433,"TCP"),
                                    (110,"TCP"),(143,"TCP")]
most_common_reg_ports_rtr_fw = [(80,"TCP"),(443,"TCP"),(22,"TCP"),(1080,"UDP")]
most_common_reg_ports_emb = [(22,"TCP"),(23,"TCP")]

# TODO: 
#   1. I need to change the structure of the target object's properties into a dictionary
#       a. This may even be a method that returns the target details in dictionary format.
# I may not need the dict of properties because they already exist as object properties.
#
#   2. Q: How do you denote that you have access to a system enough to progress past it?
#       A: To progress past a target, (ie. scan/exploit past) you must have a RAT or implant on the target.
#       Q: How will you denote that an exploit session is associated with an implant/install session
#           ie. you exploit and implant the same system in a sequince. 
#       A: When the actions are taken on the target the "capre_deployed_to_target"'s timestamp value is checked.
#           If the latest exploit time is within 'X' number of minutes it will not require the reexploit of the target.


target = {
    "type":"",
    "function":"",
    "open_ports":[],
    "firewall_status": bool,
    "WAF": bool,
    "layer": int,
    "EDR": bool,
    "capabilities_used":[],
    "attacker_detected": bool,
    }

class targetSystem():
    def __init__(self, system_type=None):
        self.type = self.determineTargetType(system_type)
        self.function = ""
        self.openPorts = []
        #self.openPorts = self._generateOpenPorts()
        self._generateOpenPorts()

        self.admin_present = False
        self.FirewallEnabled = False
        self.WAF = False
        #self.layer = 0
        self.EDR = False
        self.ALLERT_TRIGGERED = False

        # target names are assigned byte the TargetNetwork object when the system is first encountered.
        # target names will be "Target 1", "Target 2" abreviated tgt1, tgt2
        self.name = None
        self.visible = False
        self.ports_visible = False
        self.access_acquired = False
        self.pri_layer = ""
        self.dual_home_visible = False # This is so that the target print wont display the dual homed nature of the target before you've surveyed the target system.
        self.alt_layer = ""
        self.bridge = False
        self.edge_node = False

        # This value will updated when the attackers utilize a tool or exploit against this target.
        #cape_details = {
        #    "type": ["tool"|"exploit"],
        #    "subtype": [...],
        #    "cape_sn": "",
        #    "burned": bool,
        #    "permissions": <user|limited service|system|kernel>
        #    "currently_present": bool,
        #    "access_instances": [],
        #}
        self.capes_deployed_to_target = []
        # cape_related_listening_ports = [[(port,proto),cape_sn], [(port,proto),cape_sn],...]
        #self.cape_related_listening_ports = []
        # the Modification_Mutex will ultimately be used to prevent modificaiton collisions. 
        self.Modification_Mutex = False

    def determineTargetType(self, system_type):
        # Embedded types may need to have a hosting system that brokers the serial connection
        # to the embedded device.
        # TODO: Add hypervisor playform type.
        self.types = ["windows","linux","router","firewall", "embedded"]
        if system_type == None:
            pos = randrange(0,5)
            return self.types[pos]
        else:
            if system_type.lower() in self.types:
                return system_type.lower()

    def _getFunction(self, usage=None):
        function_types = ["user system","admin system","file server","web server","domain controller",
                          "email server","random victim","router","firewall", "weapon system", "scada"]
        if usage == None:
            if (self.type == self.types[0]):
                pos = randrange(0,6)
                self.function = function_types[pos]
            elif (self.type == self.types[1]):
                pos = randrange(0,10)
                self.function = function_types[pos]
            elif (self.type == self.types[2]):
                self.function = function_types[7]
            elif (self.type == self.types[3]):
                self.function = function_types[8]
            elif (self.type == self.types[4]):
                pos = randrange(9,10)
                self.function = function_types[pos]
            else:
                print("[Failure] Target function generation failed.")

        else:
            if usage.lower() in function_types:
                self.function = usage.lower()

    def _makeAChoice(self) -> bool:
        if randrange(0,20) > 15:
            return True
        else:
            return False

    def _choosePortsFromSelection(self,ports) -> list:
        num_of_ports = len(ports)
        num_of_open_ports = 0
        if num_of_ports > 1:
            num_of_open_ports = randrange(0, num_of_ports)
        elif num_of_ports == 1:
            num_of_open_ports = randrange(0, num_of_ports)
        elif num_of_ports == 0:
            num_of_open_ports = 0 

        selected_ports = []
        loop_count = num_of_open_ports
        while loop_count > 0:
            if self._makeAChoice():
                selected_ports.append(ports[loop_count])
            loop_count -= 1

        return selected_ports

    def _generateOpenPorts(self) -> None:
        registered_port_range = (0, 1023)
        tgt_specific_registered_ports = []
        ephemeral_port_range = (1024, 65535)
        tgt_specific_ephemeral_ports = []

        if self.type == "linux":
            #most_common_client_reg_ports_nix = [(22,"TCP")]
            #most_common_server_reg_ports_nix = [(80,"TCP"),(443,"TCP"),(22,"TCP"),(21,"TCP"),
            #                                    (23,"TCP"),(25,"TCP"),(69,"TCP"),(110,"TCP"), 
            #                                    (123,"TCP"),(514,"UDP"),(8008,"TCP")]
            global most_common_client_reg_ports_nix
            global most_common_server_reg_ports_nix
            for port in self._choosePortsFromSelection(most_common_client_reg_ports_nix):
                tgt_specific_registered_ports.append(port)
            for port in self._choosePortsFromSelection(most_common_server_reg_ports_nix):
                tgt_specific_registered_ports.append(port)

        elif self.type == "windows":
            #most_common_client_reg_ports_win = [(135,"TCP"),(137,"UDP"),(137,"TCP"),(138,"UDP"),(139,"TCP"),
            #                                    (445,"TCP"),(3389,"TCP")]
            #most_common_server_reg_ports_win = [(80,"TCP"),(443,"TCP"),(8080,"TCP"),(53,"UDP"),(1433,"TCP"),
            #                                    (110,"TCP"),(143,"TCP")]
            global most_common_client_reg_ports_win
            global most_common_server_reg_ports_win

            for port in self._choosePortsFromSelection(most_common_client_reg_ports_win):
                tgt_specific_registered_ports.append(port)
            for port in self._choosePortsFromSelection(most_common_server_reg_ports_win):
                tgt_specific_registered_ports.append(port)

        elif ((self.type == "router") or (self.type == "firewall")):
            #most_common_reg_ports_rtr_fw = [(80,"TCP"),(443,"TCP"),(22,"TCP"),(1080,"UDP")]
            global most_common_reg_ports_rtr_fw

            for port in self._choosePortsFromSelection(most_common_reg_ports_rtr_fw):
                tgt_specific_registered_ports.append(port)


        elif self.type == "embedded":
            #most_common_reg_ports_emb = [(22,"TCP"),(23,"TCP")]
            global most_common_reg_ports_emb

            for port in self._choosePortsFromSelection(most_common_reg_ports_emb):
                tgt_specific_registered_ports.append(port)


        else:
            print("[!] ERROR: Provided Target System Type Is Not Implemented")

        #print(tgt_specific_registered_ports)
        for port in tgt_specific_registered_ports:
            self.openPorts.append(port)
        # implementation of ephemeral port selection needed.
        for port in tgt_specific_ephemeral_ports:
            self.openPorts.append(port)

    def printTargetDetails(self) -> None:
        # header
        print("---------------------------------------------------------------------")
        #print(f"\tTarget: {self.name}")
        #print(f"\t    \___ Access: {self.access_acquired}")
        #print(f"\t    \___ Function: {self.function}")
        #print(f"\t    \___ Target Type: {self.type}")
        #print(f"\t    \___ Open Ports: {self.openPorts}")
        #print(f"\t    \___ Capes on target:")
        print(f" Target: {self.name}, Access: {self.access_acquired}, OS: {self.type}")
        print(f"    Visible Ports: {self.openPorts}")
        if self.access_acquired:
            print(f"    System details: EDR:{self.EDR}, FW:{self.FirewallEnabled}, Function:{self.function}")
            print(f"    Edge Node: {self.edge_node}, Dual Homed: {self.bridge}, Pri Net Seg: {str(self.pri_layer)}, Alt Net Seg: {str(self.alt_layer)}")
        else:
            print(f"    Edge Node: {self.edge_node}, Pri Net Seg: {str(self.pri_layer)}")
        
        print("    Capes Deployed to target.")
        print("       TYPE        | CAPE_SN | BURNED | PERMISSIONS | PRESENT | INSTANCE_ID | SRC_INSTANCE_ID")

        for tool in self.capes_deployed_to_target:
            #print(f"    Cape deployed: {tool}")
            print("       {0:11} | {1:7} | {2:6} | {3:11} | {4:7} | {5:11} | {6:11}".format(tool["subtype"],tool["cape_sn"],str(tool["burned"]),tool["permissions"],str(tool["currently_present"]),str(tool["instance_id"]),str(tool["src_instance_id"])))
            #print(f"\t        \___ {tool}")
        print("---------------------------------------------------------------------")
        return

    def makeVisible(self) -> None:
        self.visible = True
        # this target is issued a target # at this point
        return  

    def results_scanSuccessful(self) -> list:
        self.ports_visible = True
        if self.FirewallEnabled:
            # if EDR enabled alert the network admin.
            return []
        return self.openPorts

    def _system_ClosePort(self, port:str) -> bool:
        for index, open_port in enumerate(self.openPorts):
            if port == open_port:
                self.openPorts.pop(index)
                return True
        return False

    def _access_ConnectToTarget(self, cape_details: dict) -> bool:
        ''' The should be used in conjunction with  TargetNetwork._target_GetTargetReference(target_name)'''
        '''
        cape_details = {
            "type": ["tool"|"exploit"],
            "subtype": [...],
            "cape_sn": "",
            "burned": bool,
            "permissions": <user|limited service|system|kernel>
            "currently_present": bool,
        }
        '''
        self.access_acquired = True
        self.capes_deployed_to_target.append(cape_details)
        return True

    # target_name can likely be removed.
    def _access_IsCapePresent(self, cape_sn: str) -> bool:
        ''' This function is called when a hacker connects to a target via an existing rat or implant. '''
        # There is an associated method call on the HackingTeam side so that the individual actor is tracking this action
        ## This may need to get information from the individual hacker object to see if it is effected by an adverse disconnect.
        
        #cape_on_target = False
        for cape in self.capes_deployed_to_target:
            if (cape['cape_sn'] == cape_sn) and (cape['currently_present']):
                print(f"[DEBUG] targeted tool present on target: {cape_sn}")
                #cape_on_target = True
                return True
                # 2. clone the tool in the capes on target list property.
                #self.capes_deployed_to_target.append(cape)

        # this return result indicates both that the tool was found
        #return cape_on_target
        return False

    def _access_IsInstancePresent(self, instance_id: str) -> bool:
        for cape in self.capes_deployed_to_target:
            if (cape['instance_id'] == instance_id):
                print(f"[DEBUG] targeted instance_id present on target: {instance_id}")
                return True
 
        return False

    #def _access_DisconnectCapeFromTarget(self, cape_sn: str) -> bool:
    def _access_DisconnectCapeFromTarget(self, instance_id: str, port: str) -> bool:
        ''' ret(True) = successfully disconnected '''
        ''' ret(False) = cape not located on the system. '''
        # If removing triggerable implant from a target the listening port needs to be removed. 
        lost_access = True
        for cape in self.capes_deployed_to_target:
            #if cape["cape_sn"] == cape_sn:
            if instance_id in cape["instance_id"]:
                cape["currently_present"] = False
            if cape["currently_present"] == True:
                lost_access = False

        if lost_access == True:
            self.access_acquired = False

        # this needs a cape_sn and not an instance_id.... I may need to create an func arg that has a default empty value
        # when value is passed it will remove the tool. this will be needed for the remove command.
        #for tool_listener in self.cape_related_listening_ports:
        #    if 

        if port != None:
            if not self._system_ClosePort(port):
                print(f"[DEBUG] ERROR: Port ({port}) associated with cape was not removed along with the cape.")
                return False

        return True

    def _access_CheckAccessMethod(self) -> list:
        ''' This will return a list of capabilities deployed to this target. ''' 
        capes = []
        for cape in self.capes_deployed_to_target:
            if cape["currently_present"] == True:
                capes.append(cape)
        return capes
        #print("[DEBUG] ERROR: Access to target, but no cape listed as tool utilized.")

    def _security_FeaturesEnabled(self) -> dict:
        features_enabled = {
            "firewall": self.FirewallEnabled,
            "EDR": self.EDR,
            }
        return features_enabled

    def _security_EnableFirewall(self) -> None:
        self.FirewallEnabled = True

    def _security_DisableFirewall(self) -> None:
        self.FirewallEnabled = False

    def _security_EnableEdr(self) -> None:
        self.EDR = True

    def _security_DisableEdr(Self) -> None:
        self.EDR = False

    def _security_ToggleAlertOn(self) -> None:
        self.ALLERT_TRIGGERED = True

    def _security_ToggleAlertOff(self) -> None:
        self.ALLERT_TRIGGERED = False

    def _exploit_ExploitThrowSuccess(self, cape_details: dict) -> bool:
        return self._access_ConnectToTarget(cape_details)

    def _exploit_ExploitThrowFailure(self, failure_result_details: dict):
        '''
        cape_details = {
            "type" : "exploit",
            "subtype" : exploit_details['subtype'],
            "cape_sn" : exploit_details["exploit_sn"],
            "burned" : decision_struct["context"].getCapeBurnedStatus(exploit_details["exploit_sn"]),
            "currently_present" : True
            }

        failure_result_details = {
            "cape": cape_details,
            "was_burned": False,
            "now_burned": False,
            "lose_pivot_system": False,
            "enable_firewall": False,
            "was_edr_enabled": False,
            "enable_edr": False,
            }
        '''
        pass

    def _upload_DeployToolToTarget_Success(self, tool_details: dict) -> bool:
        cape_details = {
            "type": "",
            "subtype": tool_details["subtype"],
            "cape_sn": tool_details["tool_sn"],
            "burned": tool_details["burned"],
            "permissions": tool_details["permissions"],
            "currently_present": True,
            "instance_id": [tool_details["instance_id"],],
            "src_instance_id": tool_details["src_instance_id"],
            }
        # all exploit sessions will be terminated upon successful rat or implant upload.
        if (tool_details["subtype"] == "rat") or (tool_details["subtype"] == "beaconing") or (tool_details["subtype"] == "triggerable"):
            cape_details["type"] == "implant" 
            for cape in self.capes_deployed_to_target:
                    if (cape["type"] == "exploit") and (cape['instance_id'] == cape_details['instance_id']):
                        cape["currently_present"] = False

        ##
        # I need to check to see if the firewall and EDR is running
        # 1. FW only can be modified
        # 2. EDR + FW will not work because FW modification will trigger the EDR
        ##
        if tool_details["subtype"] == "triggerable":
            self.openPorts.append(tool_details["port"])
            #if [(tool_details['port'],tool_details['tool_sn'])] not in self.cape_related_listening_ports:
            #    self.cape_related_listening_ports.append([(tool_details['port'],tool_details['tool_sn'])])
        self.capes_deployed_to_target.append(cape_details)
        return True

    def _upload_DeployToolToTarget_Failure(self, tool_details: dict):
        pass



class TargetNetwork():
    def __init__(self, size):
        self.size = 0
        if size.lower() == 'small':
            self.size = 15
        elif size.lower() == 'medium':
            self.size = 30
        elif size.lower() == 'large':
            self.size = 50
        elif size.lower() == 'huge':
            self.size = 100

        self.edge_nodes = []
        self.Targets = self._generateTargets()
        self._constructNetworkArchitecture()
        # self.edge_nodes is populated with numbers which are offsets into the self.Targets varable.
        self.edge_nodes = self.generate_ListOfEdgeNodes()
        # self.mission_target is a number offset into the self.Target variable.
        self.mission_target = []
        self.mission_target = self.Targets[self._selectMissionTarget()]
        # Need to flesh out the setting of "admin_skill_level"
        admin_difficulty = "easy"
        self._constructAdministrator(admin_difficulty)

        self.target_name_tracking = []

    # values for administrator skill need to be determined and set.
    def _constructAdministrator(self,admin_difficulty) -> None:
        # needs another thread to populate alert queue when alerts trigger in the network.

        #network_administration = 0
        #malware_analysis = 0 
        #scripting = 0
        #work_load = 0
        '''
        if admin_difficulty == "easy":
            network_administration = 0
            malware_analysis = 0 
            scripting = 0
            work_load = 0

        elif admin_difficulty == "medium":
            network_administration = 0
            malware_analysis = 0 
            scripting = 0
            work_load = 0

        elif admin_difficulty == "hard":
            network_administration = 0
            malware_analysis = 0 
            scripting = 0
            work_load = 0

        else:
            raise Exception("[!] ERROR: Administrator's skill level not recognized.")

        self.administrator = {
            "network_administration": network_administration,
            "malware_analysis": malware_analysis,
            "scripting": scripting,
            "work_load": work_load,
            "aggressiveness": 0,
            }
        '''

        alert_queue = []
        # call the initilization of the admin team
        
        # initlize the queue polling thread.
        # need to create alert reaction method that is called from within polling thread.


        return

    def _getPercentNumber(self, percentage, whole):
        return (percentage * whole) / 100

    def _getNumberPercentage(self, whole, part):
        return 100 * float(part)/float(whole)

    def _EdgeNodeInRange(self, percent):
        if percent > 20:
            return False
        else:
            return True

    def _generateTargets(self):
        node_count = self.size
        Targets = []
        while node_count > 0:
            generated_target = targetSystem()
            edge_node = False
            mission_target = False
            if self._EdgeNodeInRange(self._getNumberPercentage(self.size, len(self.edge_nodes))):
                if randrange(0,20) > 15:
                    edge_node = True
                    generated_target.edge_node = True
                    while generated_target.openPorts == []:
                        generated_target._generateOpenPorts()

            #layer_bridge = False
            # layer_bridge = [<is bridge>, <pri_layer>, <alt_layer>]
            layer_bridge = [False,0,0]
            # The target_body variable needs to be changed to reflect the target dictionary
            # this will prevent downstream lookup of list offset value type.
            target_body = [generated_target, edge_node, mission_target, layer_bridge]
            #target_body = {
            #    "generated_target": generated_target,
            #    "edge_node": edge_node,
            #    "mission_target": mission_target,
            #    "layer_bridge": [<is bridge>, <alt_layer>],
            #    }
            Targets.append(target_body)
            node_count -= 1
            #print(target_body)
        return Targets

    def generate_ListOfEdgeNodes(self) -> list:
        edge_nodes = []
        for index, target in enumerate(self.Targets):
           if target[1]:
               #edge_nodes.append(index)
               edge_nodes.append(target)

        # this if statement never seems to run... I think its functionality is implemented in _generateTargets
        if edge_nodes == []:
            edge_node_percentage = 0
            while edge_node_percentage <= 20:
                selection = randrange(0,len(self.Targets))
                if selection not in edge_nodes:
                    edge_nodes.append(selection)
                    edge_node_percentage = self._getNumberPercentage(len(self.Targets) ,len(edge_nodes))
                else:
                    pass

        return edge_nodes

    def results_enumerateEdgeNodes(self) -> list:
        edge_nodes = self.edge_nodes
        results = []
        # There is a bug where the edge_nodes are just a list of int numbers
        # I think this bug occurs when the length value is passed instead of a legit target value
        for node in edge_nodes:
            if node[0].name == None:
                self.establish_targetName(node[0])

            # Results are generated here and returned to the threaded worker instead of just making the ports
            # visible because it will allow for when the firewall or EDR is enabled to change subsequent scans.
            results.append({"name": node[0].name} | self.results_enumerateTarget(node[0]))

        return results

    def results_enumerateNetworkSegment(self, source_target_name: str) -> list:
        # context is from a system you're currently performing that action from.
        #target.makeVisible()


        src_system = self._target_GetTargetReference(source_target_name)

        affected_targets = []
        for target in self.Targets:
            if (target[0].pri_layer == src_system.pri_layer) or ((target[0].alt_layer == src_system.alt_layer) and src_system.alt_layer != 0) or (target[0].pri_layer == src_system.alt_layer):
                target[0].makeVisible()
                self.establish_targetName(target[0])
                target[0].results_scanSuccessful()
                affected_targets.append(target[0])

        return affected_targets

    def establish_targetName(self, target_reference):
        node_has_no_name = True
        for name in self.target_name_tracking:
            if target_reference.name == name:
                node_has_no_name = False

        if node_has_no_name:
            num = len(self.target_name_tracking)
            target_reference.name = f"target {num+1}"
            self.target_name_tracking.append(f"target {num+1}")
            
    def results_enumerateTarget(self, target_reference) -> dict:
        target_reference.ports_visible = True
        target_reference.makeVisible()
        results = {
            "os_type": target_reference.type,
            "open_ports": target_reference.results_scanSuccessful()
            }
        return results

    def _selectMissionTarget(self):
        # if the mission target does not have any open ports the object needs to be modified to create at least 1
        if len(self.mission_target) == 0:
            mission_target_index = randrange(0,len(self.mission_target)+1)
        else:
            mission_target_index = randrange(0,len(self.mission_target))
        #print(f"Mission_Target_Index: {mission_target_index}")
        self.Targets[mission_target_index][2] = True
        return mission_target_index

    def _populateNetworkLayers(self, number_of_layers):
        # Layers are used to determine the ability for targets to directly communicate laterally.
        #self.NetworkLayout.update({"Layer_1" : []})
        targets = deepcopy(self.Targets)
        new_targets = []
        
        # TODO: Hypervisor target accessability needs to be determined once that platform is added.

        # Tasks
        # 1. determine how many layers were passed and divide it by the number of targets
        initial_layer_split = len(targets) / number_of_layers
        # 2. do a random range to successively build out the layers
        initial_layer_breakout = []
        target_num_total = 0
        layer_counter = 0
        while (target_num_total <= len(targets)):
            target_num = randrange(1, int(initial_layer_split) + 2)
            target_num_total += target_num
            if target_num_total > len(targets):
                target_num_total -= target_num
                target_num =  (len(targets) - target_num_total)
                target_num_total += target_num
                initial_layer_breakout.append(target_num)
                break
            elif (layer_counter <= len(initial_layer_breakout)) and (target_num_total < len(targets)):
                #target_num += len(targets) - target_num_total
                initial_layer_breakout.append(target_num)
            elif (layer_counter == len(initial_layer_breakout)) and (target_num_total < len(targets)):
                target_num += len(targets) - target_num_total
                initial_layer_breakout.append(target_num)
            else:
                #target_num += len(targets) - target_num_total
                initial_layer_breakout.append(target_num)
            layer_counter += 1
        if target_num_total != len(targets):
            print(f"[!] ERROR: target_num_total:{target_num_total} != len(targets): {len(targets)}.")
        
        # 3. construct the layers and populate them with targets
        total_target_counter = 0
        for index, targets_in_layer in enumerate(initial_layer_breakout):
            layer_target_counter = 0
            layer_targets = []

            dual_homed_systems = 0
            if (initial_layer_breakout[index] >= 0) and (initial_layer_breakout[index] <= 4):
                dual_homed_systems = 1
            else:
                dual_homed_systems = randrange(1,int(initial_layer_breakout[index]/2))

            if dual_homed_systems > initial_layer_breakout[index]:
                dual_homed_systems = initial_layer_breakout[index]
            key = "Layer_" + str(index+1)
            while layer_target_counter < targets_in_layer:
                if dual_homed_systems > 0:
                    targets[0][3][0] = True
                    dual_homed_systems -= 1

                targets[0][0].bridge = targets[0][3][0]
                targets[0][3][1] = int(key.split("_")[-1])
                targets[0][0].pri_layer = targets[0][3][1]
                layer_targets.append(targets[0])
                ## New code
                self.Targets[total_target_counter].append(key)
                total_target_counter += 1
                ## end new code
                #new_targets.append(targets)
                targets.pop(0)
                layer_target_counter += 1
            #key = "Layer_" + str(index+1)
            if layer_target_counter == 0:
                pass
            else:
                self.NetworkLayout.update( {key : layer_targets})

    def _constructNetworkArchitecture(self):
        self.NetworkLayout = {}
        if self.size == 15:
            number_of_layers = randrange(1,3)
            self._populateNetworkLayers(number_of_layers)
        elif self.size == 30:
            number_of_layers = randrange(1,4)
            self._populateNetworkLayers(number_of_layers)
        elif self.size == 50:
            number_of_layers = randrange(1,5)
            self._populateNetworkLayers(number_of_layers)
        elif self.size == 100:
            number_of_layers = randrange(1,6)
            self._populateNetworkLayers(number_of_layers)
        else:
            print(f"[!] ERROR: Network size \'{self.size}\' not implemented.")

        end_layer_count = 0
        for index, layer in enumerate(list(self.NetworkLayout.keys())):
            try:
                for target in self.NetworkLayout[layer]:
                    pass
            except:
                self.NetworkLayout.pop(index)
        

        end_layer_count = len(self.NetworkLayout)
        print(f"Layer Count: {len(self.NetworkLayout)}={end_layer_count}")
        if end_layer_count == 1:
            for index, layer in enumerate(list(self.NetworkLayout.keys())):
                    for target in self.NetworkLayout[layer]:
                        target[3][0] = False

        # layer_bridge = [<is bridge>, <pri_layer>, <alt_layer>]
        # target_body = [generated_target, edge_node, mission_target, layer_bridge]

        else:
            layer_numbers = []
            while end_layer_count > 0:
                layer_numbers.append(end_layer_count)
                end_layer_count -= 1
            # randomize network layers for assignment.
            shuffle(layer_numbers)
            #print(f"[DEBUG] Layer numbers produced: {layer_numbers}")
            print(f"[DEBUG] Shuffled layer_numbers: {layer_numbers}")
            layer_number_counter = len(layer_numbers) - 1
            for index, layer in enumerate(list(self.NetworkLayout.keys())):
                for target in self.NetworkLayout[layer]:
                    if target[0].bridge == True:
                        if (target[0].pri_layer == layer_numbers[layer_number_counter]) or (target[3][1] == layer_numbers[layer_number_counter]):
                            failed_already = 0
                            while True:
                                get_random_layer = 0 
                                try:
                                    # failure can occur here when there are only 1 or 2 network segments and the ranrange line below returns a bad number indefinately.
                                    if len(layer_numbers) == 2:
                                        failed_already += 1
                                        get_random_layer = layer_numbers[failed_already]
                                    else:
                                        get_random_layer = randrange(1,len(layer_numbers))
                                        #if (get_random_layer == 1) or (get_random_layer == 0):
                                        #    continue
                                    if (layer_numbers[get_random_layer] == layer_numbers[layer_number_counter]):
                                        continue
                                except:
                                    break
                                target[0].alt_layer = layer_numbers[get_random_layer]
                                target[3][2] = layer_numbers[get_random_layer]                        
                                print(f"[DEBUG] 1: Issued bridge alt_layer {layer_numbers[get_random_layer]} to pri_layer {target[0].pri_layer}")
                                break
                        else:
                            target[0].alt_layer = layer_numbers[layer_number_counter]
                            target[3][2] = layer_numbers[layer_number_counter]
                            print(f"[DEBUG] 2: Issued bridge alt_layer {layer_numbers[layer_number_counter]} to pri_layer {target[0].pri_layer}")
                        if layer_number_counter == 0:
                            layer_number_counter = len(layer_numbers) - 1 
                        else:
                            layer_number_counter -= 1


        print()
        new_target_list = []
        for index, layer in enumerate(list(self.NetworkLayout.keys())):
            print(f"Layer_{index+1}")
            try:
                for target in self.NetworkLayout[layer]:
                    print(f"target: {target}")
                    target[0].pri_layer = target[3][1]
                    target[0].alt_layer = target[3][2]
                    target[0].bridge = target[3][0]
                    new_target_list.append(target)

            except:
                print(f"target: []")

        
        self.Targets = new_target_list
        for target in self.Targets:
            target[0].pri_layer = target[3][1]
            target[0].alt_layer = target[3][2]
            target[0].bridge = target[3][0]            

        return

    def results_targetList(self) -> None:
        for target in self.Targets:
            if (target[0].visible) and (target[0].ports_visible):
                target[0].printTargetDetails()

        return        

    def _target_GetTargetReference(self, target_name: str) -> object:
        for target in self.Targets:
            if target_name == target[0].name:
                return target[0]

    def _exploit_checkIfValid(self, exploit_details) -> bool:
        if exploit_details['target'] not in self.target_name_tracking:
            print(f"[DEBUG] target name was not found in tracked target list")
            print(f"[DEBUG] Tracked target list:")
            print(f"{self.target_name_tracking}")
            return False
        for target in self.Targets:
            if target[0].name == exploit_details['target']:
                if target[0].visible and target[0].ports_visible:
                    print("[DEBUG] Target is visible and ports are visible.")
                    for open_port in target[0].openPorts:
                        try:
                            if str(open_port[0]) == str(exploit_details['port'][0]):
                                print("[DEBUG] targeted port is open.")
                                return True
                        except: # if port = None for LPE 
                            return True
        print("[DEBUG] Some other error occured in _exploit_checkIfValid.")
        return False

    def _access_checkTargetNameValid(self, target_name: str) -> bool:
         for target in self.Targets:
            if target_name == target[0].name:
                return True
         return False

    def _access_checkIfAccessIsAcquired(self, target_name: str) -> bool:
        for target in self.Targets:
            if target_name == target[0].name:
                if target[0].access_acquired == True:
                    return True
        return False

    def _access_DetermineIfDetected(self, target_name: str) -> bool: 
        ''' Used to determine if actions taken on a target were detected by the Administrator security product/logs '''
        for target in self.Targets:
            if target_name == target[0].name:
                if target[0].ALLERT_TRIGGERED == True:
                    return True
        return False

    def _access_NarrativeCapeFailureCause(self, failure_result_details: dict) -> str:
        ''' Generated a narrative based reasoning for why the failure occured. ie. host process crash '''

        # subtype is the secondary value below tool|exploit. ie. rce, beaconing, etc.
        # failures which one to return to the user as the cause of the failure.
        #   ex. host|exploited process crashed for unknown reasons
        #       triggered EDR, Administrator killed host process|session|etc., network connectivity issues caused cape to exit.
        #       error in cape caused cape to exit without issue, cape crashed the target system.
        #       LP|C2 burned in malware report lost implant and redirector.
        
        # I think that the failure conditions need to be tracked by the PlayerUtils.HackingTeam._values_ExploitTargetDecision()

        if failure_result_details['cape']["subtype"] == 'rce':
            return (f'''[Narrator] sub_type:{failure_result_details['cape']['subtype']} 
was_burned: {failure_result_details['was_burned']}
now_burned: {failure_result_details['now_burned']}
lose_pivot_system: {failure_result_details['lose_pivot_system']}

enable_firewall: {failure_result_details['enable_firewall']}
was_edr_enabled: {failure_result_details['was_edr_enabled']}
enable_edr: {failure_result_details['enable_edr']}
            ''')

        elif failure_result_details['cape']["subtype"] == 'lpe':
            return (f'''[Narrator] sub_type:{failure_result_details['cape']['subtype']} 
was_burned: {failure_result_details['was_burned']}
now_burned: {failure_result_details['now_burned']}
lose_pivot_system: {failure_result_details['lose_pivot_system']}
enable_firewall: {failure_result_details['enable_firewall']}
was_edr_enabled: {failure_result_details['was_edr_enabled']}
enable_edr: {failure_result_details['enable_edr']}
            ''')

        elif failure_result_details['cape']["subtype"] == 'lateral':
            return (f'''[Narrator] sub_type:{failure_result_details['cape_subtype']} 
was_burned: {failure_result_details['was_burned']}
now_burned: {failure_result_details['now_burned']}
lose_pivot_system: {failure_result_details['lose_pivot_system']}
enable_firewall: {failure_result_details['enable_firewall']}
was_edr_enabled: {failure_result_details['was_edr_enabled']}
enable_edr: {failure_result_details['enable_edr']}
            ''')

        elif failure_result_details['cape']["subtype"] == 'credentials':
            return (f'''[Narrator] sub_type:{failure_result_details['cape_subtype']} 
was_burned: {failure_result_details['was_burned']}
now_burned: {failure_result_details['now_burned']}
lose_pivot_system: {failure_result_details['lose_pivot_system']}
enable_firewall: {failure_result_details['enable_firewall']}
was_edr_enabled: {failure_result_details['was_edr_enabled']}
enable_edr: {failure_result_details['enable_edr']}
            ''')

        else:
            print(f"[DEBUG] ERROR: {failure_result_details['cape']['subtype']} is not valid exploit sub_type.")
            return ""

    def _access_DisconnectFromTarget_General(self, target_disconnect_struct: dict) -> bool:
        ''' called when legitimately disconnecting from a tool on target. '''
        '''
        disconnect_struct = {
            "context": "",
            "intial_target": "",
            "cape_sn": "",
            "cape_type": exploit|implant,
            "scope": [individual|all],
            "effected_targets": [],
            "initiated_by": [system|player]
        }
        '''
        '''
        target_disconnect_struct ={
            "target": target["targeted_system"],
            "cape_sn": target["cape_sn"],
            "src_system": target["src"],
            "src_cape": target["src_cape"],
            }
        '''

        # The disconnect_struct will be reconstructed each time a target is disconnected from


        # if (cape_type != implant | tool) or (cape_subtype != beaconing | triggerable) 
        #   change to not currently present on target.

        target_ref = self._target_GetTargetReference(target_disconnect_struct['target'])

        #ret_status = target_ref._access_DisconnectCapeFromTarget(target_disconnect_struct['cape_sn'])
        ret_status = target_ref._access_DisconnectCapeFromTarget(target_disconnect_struct['instance_id'], target_disconnect_struct['port'])
        if ret_status:
            return True
        else:
            return False
            


    def _access_DisconnectFromUpstreamSystems_General(self, disconnect_struct: dict) :
        # potentially remove function defenition
        '''
        disconnect_struct = {
            "context": "",
            "intial_target": "",
            "cape_sn": "",
            "scope": [individual|all],
            "effected_targets": [],
            "initiated_by": [system|player]
        }
        '''
    


        pass


    def _access_DisconnectFromTarget_Failure(self, disconnect_struct: dict) -> bool:
        ''' called by HackingTeam._access_FailedDeployToolToTarget() '''
        pass

    def _access_CheckInterTargetConnectivity(self, source_target_name: str, target_name: str) -> bool:

        source_layer = 0
        source_bridge = False
        source_edge = False
        source_alt_layer = 0

        target_bridge = False
        target_layer = 0
        target_alt_layer = 0
        target_edge = False
        for target in self.Targets:
        #for target in self.NetworkLayout:
            print(f"-- target name: {target[0].name}")
            if target[0].name == source_target_name:
                #source_layer = int(target[3][1], 10)
                source_layer = target[3][1]
                source_bridge = target[3][0]
                source_alt_layer = target[3][2]
                source_edge = target[1]
            if target[0].name == target_name:
                # target[3][1] is returning 0 because it has 0 as the source and target 
                #target_layer = int(target[3][1], 10)
                target_layer = target[3][1]
                target_bridge = target[3][0]
                target_alt_layer = target[3][2]
                target_edge = target[1]

        can_communicate_internally = False
        if source_layer == target_layer:
            can_communicate_internally = True
        #elif source_target_layer != target_layer:
        else:
            # 1. source alt layer == tgt pri_layer 
            if source_alt_layer == target_layer:
                can_communicate_internally = True
            # 2. source pri layer == tgt alt_layer
            if source_layer == target_alt_layer:
                can_communicate_internally = True
            # 3. source alt_layer == tgt alt_layer
            if source_alt_layer == target_alt_layer:
                can_communicate_internally = True

        can_communicate_externally = False
        if source_edge and target_edge:
            can_communicate_externally = True

        if can_communicate_internally or can_communicate_externally:
            return True
        else:
            return False




