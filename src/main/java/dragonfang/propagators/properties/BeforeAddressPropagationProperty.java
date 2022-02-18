package dragonfang.propagators.properties;

import java.util.HashSet;
import java.util.Set;

import dragonfang.entities.Entity;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;

public class BeforeAddressPropagationProperty extends AbstractPropagationProperty {

	@Override
	public Set<Entity> getPropagatedEntities(Entity entity, Set<Entity> allCandidateSet) {

		Set<Entity> propFuncSet = new HashSet<Entity>();

		Listing listing = entity.getProgram().getListing();
		CodeUnit codeUnit = listing.getCodeUnitBefore(entity.getAddresses().getMinAddress());

		Address address = codeUnit.getAddress();
		Entity beforeEntity = listing.getFunctionContaining(address);

		if (beforeEntity == null)
			return propFuncSet;

		propFuncSet.add(beforeEntity);
		return processCandidates(propFuncSet, allCandidateSet);
	}

	@Override
	public String getName() {
		return "Before Address Propagation Property";
	}
}
