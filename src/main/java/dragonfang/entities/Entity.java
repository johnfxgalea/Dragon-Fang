package dragonfang.entities;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

/**
 * 
 * Comparison entity which essentially dictates the granularity of the matching
 * process.
 *
 */
public abstract class Entity
{

    public enum GranularityType { BASIC_BLOCK, FUNCTION }

    private GranularityType granularityType;

    public Entity(GranularityType granularityType)
    {
        this.granularityType = granularityType;
    }

    public GranularityType getGranularity()
    {
        return granularityType;
    }

    public abstract Program getProgram();

    public abstract AddressSetView getAddresses();
}
