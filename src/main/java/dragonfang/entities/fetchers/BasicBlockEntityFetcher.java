package dragonfang.entities.fetchers;

import dragonfang.entities.BasicBlockEntity;
import dragonfang.entities.Entity;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class BasicBlockEntityFetcher implements EntityFetcher {

	private Program program;
	private BasicBlockModel basicBlockModel;

	public BasicBlockEntityFetcher(Program program) {
		this.program = program;
		this.basicBlockModel = new BasicBlockModel(program);
	}

	@Override
	public Entity getEntityAt(Address address, TaskMonitor monitor) throws CancelledException{
		
		CodeBlock codeBlock = basicBlockModel.getCodeBlockAt(address, monitor);
		return new BasicBlockEntity(codeBlock, program);
	}
}
