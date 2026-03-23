class ThreatMemory:
    def __init__(self, alpha=0.7):
        self.memory = {}
        self.alpha = alpha

    def update(self, entity_id, predicted_risk):
        prev = self.memory.get(entity_id, 0)
        updated = self.alpha * prev + (1 - self.alpha) * predicted_risk
        self.memory[entity_id] = updated
        return updated

    def get_risk(self, entity_id):
        return self.memory.get(entity_id, 0)
