package dragonfang.entities.fetchers;

import dragonfang.entities.Entity;
import dragonfang.entities.FunctionEntity;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class FunctionEntityFetcher implements EntityFetcher
{

    private Listing listing;

    public FunctionEntityFetcher(Program program)
    {
        this.listing = program.getListing();
    }

    @Override
    public Entity getEntityAt(Address address, TaskMonitor monitor)
        throws CancelledException
    {
        Function function = listing.getFunctionContaining(address);
        if (function == null)
            return null;

        return new FunctionEntity(function);
    }
}
