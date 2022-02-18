package dragonfang.entities;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

public class BasicBlockEntity extends Entity{

	public BasicBlockEntity()
	{
		super(GranularityType.BASIC_BLOCK);
	}

	@Override
	public Program getProgram() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public AddressSetView getAddresses() {
		// TODO Auto-generated method stub
		return null;
	}
}
