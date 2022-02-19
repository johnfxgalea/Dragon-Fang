package dragonfang.entities;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Program;

public class BasicBlockEntity extends Entity{

	private CodeBlock codeBlock;
	private Program program;
	
	public BasicBlockEntity(CodeBlock codeBlock, Program program)
	{
		super(GranularityType.BASIC_BLOCK);
		this.codeBlock = codeBlock;
		this.program = program;
	}

	@Override
	public Program getProgram() {
		return program;
	}

	@Override
	public AddressSetView getAddresses() {
		// TODO Auto-generated method stub
		return null;
	}
}
