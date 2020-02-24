"""
def  compat_node(g1,g2,n1,n2):
    node1=g1.vs[n1]
    node2=g2.vs[n2]
    if node1["classe"]==node2["classe"]:
        #print("node ", n1," ",node1.attributes()["name"], "in graph source of class", node1.attributes()["classe"], " matches node", n2," ",node2.attributes()["name"], "in graph dest of class",
#              node2.attributes()["classe"])

        return  True
    else:
        return False
def compat_edges(g1,g2,e1, e2):
    to_check=relations[g1.vs[g1.es[e1].source]["classe"]][g1.vs[g1.es[e1].target]["classe"]]
#    if to_check==None:

    source1=g1.vs[g1.es[e1].source]
    target1=g1.vs[g1.es[e1].target]
    source2=g2.vs[g2.es[e2].source]
    target2=g2.vs[g2.es[e2].target]
    try:
        for rel in to_check:
            if g1.es[e1].attributes()[rel] != g2.es[e2].attributes()[rel]:
                return False
        #print("edge ",e1,"in graph source between node",source1.attributes()["name"],"and ",target1.attributes()["name"],"of relation",rel," matches edge",e2,"in graph dest between node",source2.attributes()["name"],"and ",target2.attributes()["name"])
        return True
    except:
        print("here")

classes=["network","machine","hacker","vuln"]
relations={}
relations["network"]={"network":["connected"],"machine":[None],"hacker":["connected"],"vuln":[None],"none":["compromised","exposed"]}
relations["machine"]={"network":["belongs_to"],"machine":[None],"hacker":[None],"vuln":["is_vulnerable"],"none":[None]}#,"none":"reachable"}
relations["hacker"]={"network":["connected"],"machine":[None],"hacker":[None],"vuln":[None],"none":[None]}
relations["vuln"]={"network":[None],"machine":[None],"hacker":[None],"vuln":[None],"none":[None]}

obj={"network":["N1","N2","N3","N4"],"machine":["M10","M20","M21","M22","M30","M40"],"vuln":["V1","V2","V3","V4","V5",],"hacker":["hacker1"]}
vulns={"M10":["V1","V2","V3"],"M20":["V1","V2","V4"],"M21":["V2","V5"],"M22":["V3"],"M30":["V1","V4"],"M40":["V5"]}
color_dict={"network":"blue","machine":"green","hacker":"red","vuln":"orange"}

gSource=Graph(directed=True)
gSource.add_vertices([b for a in obj for b in obj[a]])
for v in gSource.vs:
    found=False
    for c in classes:
        if v["name"] in obj[c]:
            v["classe"]=c
            v["color"] =color_dict[c]
            found=True
    if not found:
        print("no color found")

    v["label"]=v["name"]


for m in vulns.keys():
    for v in vulns[m]:
        gSource.add_edge(m, v, is_vulnerable=True,color="red")
gSource.add_edge("hacker1","N1",connected=True)
gSource.add_edge("N1","hacker1",connected=True)

gSource.add_edge("N1","N2",connected=True)
gSource.add_edge("N2","N1",connected=True)

gSource.add_edge("N1","N3",connected=True)
gSource.add_edge("N3","N1",connected=True)

gSource.add_edge("N3","N2",connected=True)
gSource.add_edge("N2","N3",connected=True)

gSource.add_edge("N3","N4",connected=True)
gSource.add_edge("N4","N3",connected=True)

gSource.add_edge("M10","N1",belongs_to=True,color="blue")
gSource.add_edge("M20","N2",belongs_to=True,color="blue")
gSource.add_edge("M21","N2",belongs_to=True,color="blue")
gSource.add_edge("M22","N2",belongs_to=True,color="blue")
gSource.add_edge("M30","N3",belongs_to=True,color="blue")
gSource.add_edge("M40","N4",belongs_to=True,color="blue")

gSource.add_edge("N1","N1",exposed=True)
#gSource.vs["label"]=["test1","test2","test3"]
#gSource.add_vertex(name="test4",label="test4",test="test")

gTarget=Graph(directed=True)
gTarget.add_vertex(name="N1",classe="network")
gTarget.add_vertex(name="N2",classe="network")
gTarget.add_vertex(name="M1",classe="machine")
gTarget.add_vertex(name="H1",classe="hacker")
gTarget.add_edge("H1","N1",connected=True)
gTarget.add_edge("N1","H1",connected=True)
gTarget.add_edge("N1","N2",connected=True)
gTarget.add_edge("N2","N1",connected=True)

gTarget.add_edge("N1","N1",exposed=True)
gTarget.add_edge("M1","N1",belongs_to=True)

layout=gSource.layout_kamada_kawai()
#plot(gSource,layout=layout,margin=200,vertex_label_dist=1)


_,_,corresp=gSource.subisomorphic_vf2(gTarget,return_mapping_21=True,node_compat_fn=compat_node,edge_compat_fn=compat_edges)
gGoal=gSource.subgraph(corresp)
layout=gGoal.layout_kamada_kawai()
plot(gGoal,layout=layout,margin=200,vertex_label_dist=1)
"""
def match(gs,gt):
    '''
    gt: target graph, classes
    gs: source graph, objects
    return: True if gt is isomorphic to a subgraph in gs, isomorphism has to keep edges' relations' truth value and vertices' classes
    '''

    pass
def intersect(g1,g2):
    '''
        g1,g2: objects graph
        return:
        '''

    pass
def classification(g):
    '''
    g: an object graph
    return: a isomorphic graph where each object is replaced by its class. Keeps edges' relations' truth value
    '''
    pass
from igraph import *
from network_attack_simulator.agents.DoormaxAgent import *
classes=["network","machine","hacker","vuln","adress"]
relations={"network":{"network":["connected"],"machine":[None],"hacker":["connected"],"vuln":[None]},\
           "machine":{"network":["belongs_to"],"machine":[None],"hacker":[None],"vuln":["is_vulnerable"],"self":[None]},\
           "hacker":{"network":["connected"],"machine":[None],"hacker":[None],"vuln":[None],"none":[None]},\
           "vuln":{"network":[None],"machine":[None],"hacker":[None],"vuln":[None],"none":[None]}}
obj={"network":["N1","N2","N3"],"machine":["M10","M20","M30"],"vuln":["V1","V2","V3"],"hacker":["hacker1"],"adress":["(1, 0)","(2, 0)","(3, 0)"]}
vulns={"M10":["V1"],"M20":["V2"],"M30":["V1","V2"]}
adjacency=[[1,1,0,0],[1,1,1,1],[0,1,1,1],[0,1,1,1]]
color_dict={"network":"blue","machine":"green","hacker":"red","vuln":"orange","adress":"yellow"}
class pickleDic(defaultdict):
    def __getitem__(self, item):
        super().__getitem__(item.write_pickle())
    def __setitem__(self, key, value):
        super().__setitem__(key.write_pickle(),value)
    def keys(self):
        keys=super().keys()
        temp=[]
        for k in keys:
            temp+=[Graph.Read_Pickle(k)]
        return temp


g1=Graph(directed=True)
g1.add_vertices([b for a in obj for b in obj[a]])
for v in g1.vs:
    found=False
    for c in classes:
        if v["name"] in obj[c]:
            v["classe"]=c
            v["color"] =color_dict[c]
            found=True
    if not found:
        print("no color found")

    v["label"]=v["name"]


for m in vulns.keys():
    for v in vulns[m]:
        g1.add_edge(m, v, is_vulnerable="Unknown")
g1.add_edge("hacker1","N1",connected=True,color="green")
g1.add_edge("N1","hacker1",connected=True,color="green")

g1.add_edge("hacker1","N2",connected=False,color="red")
g1.add_edge("N2","hacker1",connected=False,color="red")

g1.add_edge("hacker1","N3",connected=False,color="red")
g1.add_edge("N3","hacker1",connected=False,color="red")

g1.add_edge("N1","N2",connected="Unknown")
g1.add_edge("N2","N1",connected="Unknown")

g1.add_edge("N1","N3",connected="Unknown")
g1.add_edge("N3","N1",connected="Unknown")

g1.add_edge("N3","N2",connected="Unknown")
g1.add_edge("N2","N3",connected="Unknown")



g1.add_edge("M10","N1",belongs_to=True,color="blue")
g1.add_edge("M20","N2",belongs_to=True,color="blue")
g1.add_edge("M30","N3",belongs_to=True,color="blue")

g1.add_edge("M10","M10",compromised=False,color="blue")
g1.add_edge("M20","M20",compromised=False,color="blue")
g1.add_edge("M30","M30",compromised=False,color="blue")

g1.add_edge("M10","(1, 0)",has_adress=True,color="blue")
g1.add_edge("M20","(2, 0)",has_adress=True,color="blue")
g1.add_edge("M30","(3, 0)",has_adress=True,color="blue")

#gSource.add_edge("N1","N1",exposed=True)
#gSource.vs["label"]=["test1","test2","test3"]
#gSource.add_vertex(name="test4",label="test4",test="test")

#gTarget=Graph(directed=True)
#gTarget.add_vertex(name="N1",classe="network")
#gTarget.add_vertex(name="N2",classe="network")
#gTarget.add_vertex(name="M1",classe="machine")
#gTarget.add_vertex(name="H1",classe="hacker")
#gTarget.add_edge("H1","N1",connected=True)
#gTarget.add_edge("N1","H1",connected=True)
#gTarget.add_edge("N1","N2",connected=True)
#gTarget.add_edge("N2","N1",connected=True)

#gTarget.add_edge("N1","N1",exposed=True)
#gTarget.add_edge("M1","N1",belongs_to=True)
g2=Graph(directed=True)
g2.add_vertices([b for a in obj for b in obj[a]])
for v in g2.vs:
    found=False
    for c in classes:
        if v["name"] in obj[c]:
            v["classe"]=c
            v["color"] =color_dict[c]
            found=True
    if not found:
        print("no color found")

    v["label"]=v["name"]


for m in vulns.keys():
    for v in vulns[m]:
        if m!="M10":
            g2.add_edge(m, v, is_vulnerable="Unknown")
        else:
            g2.add_edge(m, v, is_vulnerable=True,color="green")
g2.add_edge("hacker1","N1",connected=True,color="green")
g2.add_edge("N1","hacker1",connected=True,color="green")

g2.add_edge("hacker1","N2",connected=False,color="red")
g2.add_edge("N2","hacker1",connected=False,color="red")

g2.add_edge("hacker1","N3",connected=False,color="red")
g2.add_edge("N3","hacker1",connected=False,color="red")

g2.add_edge("N1","N2",connected=True,color="green")
g2.add_edge("N2","N1",connected=True,color="green")

g2.add_edge("N1","N3",connected=True,color="green")
g2.add_edge("N3","N1",connected=True,color="green")

g2.add_edge("N3","N2",connected="Unknown")
g2.add_edge("N2","N3",connected="Unknown")



g2.add_edge("M10","N1",belongs_to=True,color="blue")
g2.add_edge("M20","N2",belongs_to=True,color="blue")
g2.add_edge("M30","N3",belongs_to=True,color="blue")

g2.add_edge("M10","M10",compromised=True,color="blue")
g2.add_edge("M20","M20",compromised=False,color="blue")
g2.add_edge("M30","M30",compromised=False,color="blue")

g2.add_edge("M10","(1, 0)",has_adress=True,color="blue")
g2.add_edge("M20","(2, 0)",has_adress=True,color="blue")
g2.add_edge("M30","(3, 0)",has_adress=True,color="blue")


g3=Graph(directed=True)
g3.add_vertices([b for a in obj for b in obj[a]])
for v in g3.vs:
    found=False
    for c in classes:
        if v["name"] in obj[c]:
            v["classe"]=c
            v["color"] =color_dict[c]
            found=True
    if not found:
        print("no color found")

    v["label"]=v["name"]


for m in vulns.keys():
    for v in vulns[m]:
        if m=="M30":
            g3.add_edge(m, v, is_vulnerable="Unknown")
        else:
            g3.add_edge(m, v, is_vulnerable=True,color="green")
g3.add_edge("hacker1","N1",connected=True,color="green")
g3.add_edge("N1","hacker1",connected=True,color="green")

g3.add_edge("hacker1","N2",connected=False,color="red")
g3.add_edge("N2","hacker1",connected=False,color="red")

g3.add_edge("hacker1","N3",connected=False,color="red")
g3.add_edge("N3","hacker1",connected=False,color="red")

g3.add_edge("N1","N2",connected=True)
g3.add_edge("N2","N1",connected=True)

g3.add_edge("N1","N3",connected=True)
g3.add_edge("N3","N1",connected=True)

g3.add_edge("N3","N2",connected=True)
g3.add_edge("N2","N3",connected=True)



g3.add_edge("M10","N1",belongs_to=True,color="blue")
g3.add_edge("M20","N2",belongs_to=True,color="blue")
g3.add_edge("M30","N3",belongs_to=True,color="blue")

g3.add_edge("M10","M10",compromised=True,color="green")
g3.add_edge("M20","M20",compromised=True,color="green")
g3.add_edge("M30","M30",compromised=False,color="blue")

g3.add_edge("M10","(1, 0)",has_adress=True,color="blue")
g3.add_edge("M20","(2, 0)",has_adress=True,color="blue")
g3.add_edge("M30","(3, 0)",has_adress=True,color="blue")
# layout=g1.layout_kamada_kawai()
# plot(g1,layout=layout,margin=200,vertex_label_dist=1)
# layout=g2.layout_kamada_kawai()
# plot(g2,layout=layout,margin=200,vertex_label_dist=1)
# layout=g3.layout_kamada_kawai()
# plot(g3,layout=layout,margin=200,vertex_label_dist=1)


# def soft_compat_edges(g1,g2,e1, e2):
#     edge1=g1.es[e1]
#     edge2=g2.es[e2]
#     try:
#         for att in edge1.attributes():
#             if edge1.attributes()[att]!=edge2.attributes()[att]:
#                 return False
#     except:
#         print("not the same attributes between ",edge1," and ",edge2)
#         return False
#     return True

a=g2.get_isomorphisms_vf2(g3,node_compat_fn=compat_node,edge_compat_fn=(lambda x,y,z,a: True))#
print(a)