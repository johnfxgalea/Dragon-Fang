package dragonfang.propagators.properties;

import java.util.HashSet;
import java.util.Set;

import dragonfang.entities.Entity;
import dragonfang.entities.fetchers.EntityFetcher;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class BeforeAddressPropagationProperty extends AbstractPropagationProperty {

	private EntityFetcher entityFetcher;

	public BeforeAddressPropagationProperty(EntityFetcher entityFetcher) {
		this.entityFetcher = entityFetcher;
	}

	@Override
	public Set<Entity> getPropagatedEntities(Entity entity, Set<Entity> allCandidateSet, TaskMonitor monitor)
			throws CancelledException {

		Set<Entity> propEntitySet = new HashSet<Entity>();

		Listing listing = entity.getProgram().getListing();
		CodeUnit codeUnit = listing.getCodeUnitBefore(entity.getAddresses().getMinAddress());
		if (codeUnit == null)
			return null;

		Address address = codeUnit.getAddress();
		Entity beforeEntity = entityFetcher.getEntityAt(address, monitor);
		if (beforeEntity == null)
			return propEntitySet;

		propEntitySet.add(beforeEntity);
		return processCandidates(propEntitySet, allCandidateSet);
	}

	@Override
	public String getName() {
		return "Before Address Propagation Property";
	}
}
