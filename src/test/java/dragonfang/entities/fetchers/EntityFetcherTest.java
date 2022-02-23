package dragonfang.entities.fetchers;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import dragonfang.AbstractDragonFangTest;
import dragonfang.entities.BasicBlockEntity;
import dragonfang.entities.Entity;
import dragonfang.entities.FunctionEntity;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class EntityFetcherTest extends AbstractDragonFangTest
{

    @Test
    public void testFunctionEntity() throws CancelledException
    {
        TaskMonitor monitor = new ConsoleTaskMonitor();

        Function simpleFunction = getSimpleFunction(builder);
        FunctionEntityFetcher fetcher = new FunctionEntityFetcher(program);
        FunctionEntity entity =
            (FunctionEntity) fetcher.getEntityAt(simpleFunction.getEntryPoint(), monitor);
        assertEquals("Function should be correct", simpleFunction, entity.getFunction());
    }

    @Test
    public void testBasicBlockEntity() throws CancelledException
    {
        TaskMonitor monitor = new ConsoleTaskMonitor();

        Function simpleFunction = getSimpleFunction(builder);
        BasicBlockModel basicBlockModel = new BasicBlockModel(program);
        CodeBlockIterator codeBlockIterator =
            basicBlockModel.getCodeBlocksContaining(simpleFunction.getBody(), monitor);
        CodeBlock codeBlock = codeBlockIterator.next();

        BasicBlockEntityFetcher fetcher = new BasicBlockEntityFetcher(program);
        BasicBlockEntity entity = (BasicBlockEntity) fetcher.getEntityAt(
            codeBlock.getFirstStartAddress(), monitor);
        assertEquals("Basic Block should be correct", codeBlock, entity.getCodeBlock());
    }
}
