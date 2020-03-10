from igraph import *

import network_attack_simulator.doormax.graphs as graphs


class Prediction:
    def __init__(self, model, effect, parameter):
        self.model = model
        self.old_models = []
        self.effect = effect
        self.parameter = parameter  # tableau: adresse ou adresse,service
        self.readableParams = [self.model.vs[i]['name'] for i in parameter]

    def updateModel(self, s, a, agent,visualize=True):
        # TODO update parameter index when removing nodes
        candidates = s.get_subisomorphisms_vf2(self.model, node_compat_fn=graphs.compat_node,
                                               edge_compat_fn=(lambda q, w, e, r: True))
        # corr=X.get_sub(Y)
        # corr[i]=j :
        # i in Y
        # j in X
        params = get_parameters(a)
        temp = deepcopy(candidates)
        for c in temp:
            for i in range(len(params)):
                try:
                    # Garder uniquement les isomorphisme dont le noeud parametre utilisé pour le modele
                    # correspond au noeud parametre utilisé dans la nouvelle situation
                    if s.vs[c[self.parameter[i]]]['name'] != params[i]:
                        candidates.remove(c)
                        break
                except:
                    print("...")
        for c in candidates:
            # TODO acquire differences for all candidates
            new = deepcopy(self.model)
            to_delete = []
            for edge in self.model.es:
                # Pour chaque arc, trouver l'arc correspondant
                try:
                    correspondingEdge = s.es[
                        s.es.select(_between=(set([c[edge.source]]), set([c[edge.target]]))).indices[0]]
                except:
                    print('dfsdf')
                for att in correspondingEdge.attributes():
                    if edge[att] != correspondingEdge[att]:
                        # print("Old value for relation",att," between",self.model.vs[edge.source].attributes()['name'],'and',self.model.vs[edge.target].attributes()['name'],':',edge[att])
                        # print("New value for corresponding edge between",s.vs[c[edge.source]].attributes()['name'],'and',s.vs[c[edge.target]].attributes()['name'],':',correspondingEdge[att],"\n")
                        to_delete += [edge]
                        break
            # TODO gerer differences si plusieurs arcs different mais de la meme facon
            if len(to_delete) > 1:
                # si plus d'une difference, et pas la meme relation:  pas le bon candidat
                att = to_delete[0].attributes()['name']
                wrongCandidate = False
                for e in to_delete[1:]:
                    if att != e.attributes()['name']:
                        wrongCandidate = True
                        break
                if wrongCandidate:
                    # passer au candidat suivant
                    continue
            for i in new.vs.indices:
                # Pour la visualisation changer le nom des noeuds par les
                # deux noms des noeuds dans le modele et la situation
                # et marquer les arcs a supprimer en gras
                new.vs[i]['label'] += '(' + s.vs[c[i]].attributes()['label'] + ')'
            for e in to_delete:
                new.es[e.index]['width'] = 4
                new.es[e.index]['color'] = 'black'
            graphs.show(new, visualize, "Differences")  # for action "+str(a)+" and effect "+str(self.effect))

            new.delete_edges(to_delete)
            # show(self.model)
            clusters = new.components(mode=WEAK)
            # Recuperer les clusters pour essayer de supprimer les noeuds isolés.
            # Si un noeud est isolé, les relations avec celui ci n'importent pas, et il
            # n'influe pas dans l'issue d'une action
            maxSize=0
            for clust in clusters:
                # Un cluster est valide si H(ou une machine compromise), et les parametres, sont inclus, et si sa taill
                maxSize=max(maxSize,len(clust))
            for clust in clusters:
                if len(clust)==maxSize:
                    if len(clust)<len(new.vs):
                        parametersChanged=True
                    else:
                        parametersChanged=False
                    new=new.subgraph(clust)
                    break

                # wrongCluster, parametersChanged = self.checkCluster(s, new, clust)
                # if not wrongCluster:
                #     new = new.subgraph(clust)
                #     if parametersChanged:
                #         new_params = []
                #         # Actualiser l'indice du/des parametre.s, si on retire des noeuds
                #         for p in self.readableParams:
                #             try:
                #                 new_params += [new.vs.select(name_eq=p).indices[0]]
                #             except:
                #                 print('issues calculating new params indexes')
                #     break
            # Verifier que H est connecté au reste du reseau

            save=deepcopy(agent)
#            if not wrongCluster:
                #    for e in new.es.select(connected=True, _from=0):
                #        if e.target != e.source:# si il ne s'agit pas de l'arc reliant H a lui-meme
            if self.effect is None:
                t = 'failure ' + a.type + str(a.target)
            else:
                t = 'pred' + a.type
            if a.type == 'exploit':
                t += str(a.service)
            print('*********************Model Update for', t, '***************************')
            for edge in to_delete:
                att = edge.attributes()['name']
                correspondingEdge = s.es[
                    s.es.select(_between=(set([c[edge.source]]), set([c[edge.target]]))).indices[0]]
                print("Old value for relation", att, " between", self.model.vs[edge.source].attributes()['name'],
                      'and', self.model.vs[edge.target].attributes()['name'], ':', edge[att])
                print("New value for corresponding edge between", s.vs[c[edge.source]].attributes()['name'], 'and',
                      s.vs[c[edge.target]].attributes()['name'], ':', correspondingEdge[att], "\n")
            graphs.show(self.model, visualize=visualize)
            graphs.show(s, visualize)
            graphs.show(new, visualize=visualize)
            self.old_models += [(self.model, s, a, self.readableParams, new)]
            self.model = new
            if parametersChanged:
                print('Old:', self.readableParams)
                print('New:', [self.model.vs[i]['name'] for i in new_params])
                self.parameter = new_params
                self.readableParams = [self.model.vs[i]['name'] for i in self.parameter]
            if agent.updateValid():
                return True
            else:
                agent=save
        return False
        # pas la meme cause:
        # self.model.get_isomorphism_vf2()

    def checkCluster(self, s, new, clust):
        namesClust = [new.vs[i].attributes()['name'] for i in clust]
        targetMachine = new.vs[new.es[new.incident(self.parameter[0], mode=ALL)[0]].source].attributes()['name']
        compromised = [s.vs[x.source].attributes()['name'] for x in s.es.select(compromised_eq=True)]
        weights = []
        for name in self.readableParams:
            if name not in namesClust:
                return True, True
        vuln = False
        for n in namesClust:
            if "V" in n:
                vuln = True
        if not vuln:
            return True, True
        for e in new.es:
            if e.attributes()['name'] in ['belongs_to', 'connected']:
                weights += [0]
            else:
                weights += [1000]
        for c in compromised:
            try:
                sub = new.get_shortest_paths(targetMachine, c, weights=weights, mode=ALL)
            except:
                raise

            sub = s.subgraph(sub[0])
            # show(sub, True)
            for e in sub.es:
                atts = e.attributes()
                if atts['name'] not in ['belongs_to', 'connected']:
                    wrongCluster = True
                    break
                else:
                    wrongCluster = False
        if len(clust) < len(new.vs):
            parametersChanged = True
        else:
            parametersChanged = False
        return wrongCluster, parametersChanged


class Effect:
    def __init__(self, objectSource, objectDest, relation, effectList):  # relation,type,value):
        self.oSrc = objectSource
        self.oDest = objectDest
        self.relation = relation
        self.potentialTypes = []
        for type, val in effectList:
            self.potentialTypes += [(type, val)]

    def __str__(self):
        return str(self.oSrc[0]).split('\n')[-1] + "\n" + str(self.oDest[0]).split('\n')[
            -1] + "\n" + self.relation + "\n" + str(self.potentialTypes)

    def __eq__(self, other):
        return graphs.multiIso(self.oSrc, other.oSrc) and graphs.multiIso(self.oDest,
                                                                          other.oDest) and self.relation == other.relation and self.potentialTypes == other.potentialTypes


def get_parameters(a):
    if a.type == 'scan':
        return [str(a.target)]
    elif a.type == 'exploit':
        return [str(a.target), 'V' + str(a.service)]
