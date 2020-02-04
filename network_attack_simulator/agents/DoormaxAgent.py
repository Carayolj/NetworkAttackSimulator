from network_attack_simulator.agents.agent import Agent
from  igraph import *
from tribool import Tribool
effect_types=["arithmetic","assignement","discovery"]
class Prediction:
    def __init__(self,model,effect):
        self.model=model
        self.effect=effect
class Effect:
    def __init__(self,object,attribute,type,value):
        #set (objetS objetD relation valeur)
        pass
class DoormaxAgent(Agent):

    def __init__(self,adress_space,topology,action_space=[("scan","adress"),("exploit","adress","service")],k=3,knowledge={}):
        self.action_space=action_space
        self.adress_space=adress_space
        self.topology_knowledge=topology
        '''
        nets=len(set([a for a,_ in adress_space]))
        self.last_compromised_net=None
        self.previous_reachable=[]
        for i in range(nets+1):
            temp=[]
            for j in range(nets+1):
                if i==j:
                    temp+=[1]
                else:
                    temp+=[2]
            self.topology_knowledge+=[temp]
        '''
        self.k=k
        if knowledge!={}:
            self.knowledge = knowledge
        else:
            self.knowledge ={"pred":{},"failure":{}}
            #self.knowledge =

    def train(self, env, num_episodes=100, max_steps=100, timeout=None, verbose=False, **kwargs):
        g=self._process_state(env._generate_initial_state())
        layout = g.layout_kamada_kawai()
        plot(g, layout=layout, margin=10, vertex_label_dist=1,edge_label_dist=2)

    def policy(self):
        pass

    def reset(self):
        pass

    def __str__(self):
        pass

    def _process_state(self, s):
        color_dict = {"network": "blue", "machine": "green", "hacker": "red", "vulnerability": "orange","adress":"yellow"}
        color_dict_edge={True:"green",False:"red","Unknown":"orange"}
        g=Graph(directed=True)
        adress_list=list(s._obs.keys())
        done=[False]
        g.add_vertex(name="H",classe="hacker")
        for i in range(len(s.service_indices)):
            g.add_vertex(name="V"+str(i),classe="vulnerability")
            #create a node for each vulnerability
        for adress in adress_list:
            id=adress_list.index(adress)
            network,_=adress
            if done[network-1]==False:
                g.add_vertex(name="N" + str(network), classe="network")
                done[network-1]=True
                done+=[False]
            g.add_vertex(name="M" + str(id), classe="machine")
            g.add_edge("M" + str(id), "N" + str(network), belongs_to=True)
            g.add_vertex(name=str(adress), classe="adress")
            g.add_edge("M" + str(id),str(adress), has_adress=True)
            if s._obs[adress]["compromised"]:
                g.add_edge("M"+str(id),"M"+str(id),compromised=True)
            for vuln in list(s._obs[adress].keys())[2:]:
                if s._obs[adress][vuln]==0:
                    val="Unknown"
                elif s._obs[adress][vuln]==1:
                    val=True
                elif s._obs[adress][vuln] == 2:
                    val=False
                g.add_edge("M"+str(id),"V"+str(vuln),is_vuln=val)
            #recuperer topologie grace aux machines accessibles
            '''
            if self.previous_reachable==[]:
                if s._obs[adress]["reachable"]:
                    #si premier etat, accessible=> exposed
                    self.topology_knowledge[0][network]=1
                    self.topology_knowledge[network][0]=1
                    self.previous_reachable+=[network]
                else:
                    self.topology_knowledge[0][network] = 0
                    self.topology_knowledge[network][0] = 0
            else:
                if self.last_compromised_net is not None:
                    if s._obs[adress]["reachable"] and network not in self.previous_reachable:
                        self.topology_knowledge[self.last_compromised_net][network] = 1
                        self.topology_knowledge[network][self.last_compromised_net] = 1                    self.previous_reachable+=[network]
                        self.previous_reachable+=[network]
                    elif not s._obs[adress]["reachable"]:
                        self.topology_knowledge[self.last_compromised_net][network] = 0
                        self.topology_knowledge[network][self.last_compromised_net] = 0
            '''

        for i in range(len(self.topology_knowledge)):
            for j in range(len(self.topology_knowledge)):
                if self.topology_knowledge[i][j]==0:
                    val=False
                elif self.topology_knowledge[i][j]==1:
                    val=True
                elif self.topology_knowledge[i][j]==2:
                    val="Unknown"
                    #TODO change by Tribool
                if i==0:
                    source="H"
                else:
                    source="N"+str(i)
                if j == 0:
                    dest="H"
                else:
                    dest="N" + str(j)
                g.add_edge(source,dest,connected=val)
        for v in g.vs:
            v["color"] = color_dict[v["classe"]]
            v["label"] = v["name"]
        for e in g.es:
            for att in e.attributes():
                if e.attributes()[att] is not None and att!="label" and att!="color":
                    e["label"]=att
                    e["color"]=color_dict_edge[e.attributes()[att]]
        return g

    def _choose_greedy_action(self, state, action_space, epsilon=0.05):
        pass