package dragonfang.primes.maps;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import dragonfang.AbstractDragonFangTest;
import dragonfang.counter.maps.InstrCountMap;
import dragonfang.counter.maps.LazyInstrCountMap;
import dragonfang.counters.PCodeInstrCounter;
import dragonfang.primes.InstrPrimeProductCalculator;
import dragonfang.primes.PCodePrimeProductCalculator;
import dragonfang.primes.Prime;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class PrimeMapTest extends AbstractDragonFangTest
{

    private long calculateActualProd()
    {

        long val = 1;

        val *= Prime.array[PcodeOp.COPY];
        val *= Prime.array[PcodeOp.LOAD];
        val *= Prime.array[PcodeOp.STORE];
        val *= Prime.array[PcodeOp.CALLIND];
        val *= Prime.array[PcodeOp.INT_EQUAL];
        val *= Prime.array[PcodeOp.INT_SLESS];
        val *= Prime.array[PcodeOp.INT_ADD];
        val *= Prime.array[PcodeOp.INT_SUB];
        val *= Prime.array[PcodeOp.INT_CARRY];
        val *= Prime.array[PcodeOp.INT_SCARRY];
        val *= Prime.array[PcodeOp.INT_AND];
        val *= Prime.array[PcodeOp.POPCOUNT];

        return val;
    }

    @Test
    public void testPrimeMap() throws CancelledException
    {

        Function simpleFunction = getSimpleFunction(builder);

        TaskMonitor monitor = new ConsoleTaskMonitor();

        InstrPrimeProductCalculator primeProduct = new PCodePrimeProductCalculator();
        InstrCountMap countMap = new LazyInstrCountMap(new PCodeInstrCounter());

        PrimeMap primeMap = new PrimeProductMap(primeProduct, countMap);
        Long val = primeMap.getPrimeProduct(simpleFunction, monitor);
        assertEquals("Prime Product should be correct", calculateActualProd(),
                     val.longValue());
    }
}
