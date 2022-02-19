package dragonfang.propagators.properties;

import java.util.HashSet;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;

public class AfterAddressPropagationProperty extends AbstractPropagationProperty
{

    @Override
    public Set<Function> getPropagatedFuncs(Function function,
                                            Set<Function> allCandidateSet)
    {

        Set<Function> propFuncSet = new HashSet<Function>();

        Listing listing = function.getProgram().getListing();
        CodeUnit codeUnit = listing.getCodeUnitAfter(function.getBody().getMaxAddress());

        Address address = codeUnit.getAddress();
        Function afterFunc = listing.getFunctionContaining(address);

        if (afterFunc == null)
            return propFuncSet;

        propFuncSet.add(afterFunc);
        return processCandidateFunctions(propFuncSet, allCandidateSet);
    }

    @Override
    public String getName()
    {
        return "After Address Propagation Property";
    }
}
