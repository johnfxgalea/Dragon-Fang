package dragonfang.propagators.properties;

import java.util.HashSet;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;

public class BeforeAddressPropagationProperty extends AbstractPropagationProperty {

	@Override
	public Set<Function> getPropagatedFuncs(Function function, Set<Function> allCandidateSet) {

		Set<Function> propFuncSet = new HashSet<Function>();

		Listing listing = function.getProgram().getListing();
		CodeUnit codeUnit = listing.getCodeUnitBefore(function.getBody().getMinAddress());
	
		Address address = codeUnit.getAddress();
		Function beforeFunc = listing.getFunctionContaining(address);
		
		if (beforeFunc == null)
			return propFuncSet;
		
		propFuncSet.add(beforeFunc);
		return processCandidateFunctions(propFuncSet, allCandidateSet);
	}

	@Override
	public String getName() {
		return "Before Address Propagation Property";
	}
}
