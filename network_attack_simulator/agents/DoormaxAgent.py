from network_attack_simulator.agents.agent import Agent


class DoormaxAgent(Agent):

    def __init__(self):
        self.actions={}


    def train(self, env, num_episodes=100, max_steps=100, timeout=None, verbose=False, **kwargs):
        pass

    def reset(self):
        pass

    def __str__(self):
        pass

    def _process_state(self, s):
        pass

    def _choose_greedy_action(self, state, action_space, epsilon=0.05):
        pass