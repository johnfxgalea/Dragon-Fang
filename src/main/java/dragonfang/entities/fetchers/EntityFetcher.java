package dragonfang.entities.fetchers;

import dragonfang.entities.Entity;
import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public interface EntityFetcher {

    /**
	 * Fetches entity at address.
	 * 
	 * @param address Address related to Entity.
	 * @return Entity at address. Null if unavailable.
	 */
    public Entity getEntityAt(Address address, TaskMonitor monitor)
        throws CancelledException;
}
