package dragonfang.entities;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public class FunctionEntity extends Entity
{

    private Function function;

    public FunctionEntity(Function function)
    {
        super(GranularityType.FUNCTION);
        this.function = function;
    }

    public Function getFunction()
    {
        return function;
    }

    @Override
    public Program getProgram()
    {
        return function.getProgram();
    }

    @Override
    public AddressSetView getAddresses()
    {
        return function.getBody();
    }

    @Override
    public boolean equals(Object obj)
    {
        if (!(obj instanceof FunctionEntity))
            return false;

        FunctionEntity cmpFuncEntity = (FunctionEntity) obj;
        return function.equals(cmpFuncEntity.function);
    }

    @Override
    public int hashCode()
    {
        return function.hashCode();
    }
}
