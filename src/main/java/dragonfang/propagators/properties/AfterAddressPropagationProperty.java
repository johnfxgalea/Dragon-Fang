package dragonfang.propagators.properties;

import java.util.HashSet;
import java.util.Set;

import dragonfang.entities.Entity;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;

public class AfterAddressPropagationProperty extends AbstractPropagationProperty {

    @Override
    public Set<Entity> getPropagatedEntities(Entity entity,
                                            Set<Entity> allCandidateSet) {

        Set<Entity> propEntitySet = new HashSet<Entity>();

        Listing listing   = entity.getProgram().getListing();
        CodeUnit codeUnit = listing.getCodeUnitAfter(entity.getAddresses().getMaxAddress());

        Address address    = codeUnit.getAddress();
        Entity afterEntity = listing.getFunctionContaining(address);

        if (afterEntity == null)
            return propEntitySet;

        propEntitySet.add(afterEntity);
        return processCandidates(propEntitySet, allCandidateSet);
    }

    @Override
    public String getName() {
        return "After Address Propagation Property";
    }
}
