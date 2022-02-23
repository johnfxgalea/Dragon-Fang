/* ###
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dragonfang;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Set;

import dragonfang.entities.Entity;
import dragonfang.entities.FunctionEntity;
import dragonfang.matchers.Match;
import dragonfang.matchers.Matcher;
import dragonfang.propagators.Propagator;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelator;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DragonFangProgramCorrelator extends VTAbstractProgramCorrelator
{
    private final String name;
    private DragonFangData dragonFangData;

    public DragonFangProgramCorrelator(ServiceProvider serviceProvider,
                                       Program sourceProgram,
                                       AddressSetView sourceAddressSet,
                                       Program destinationProgram,
                                       AddressSetView destinationAddressSet,
                                       ToolOptions options, String name,
                                       DragonFangData dragonFangData)
    {
        super(serviceProvider, sourceProgram, sourceAddressSet, destinationProgram,
              destinationAddressSet, options);

        this.name = name;
        this.dragonFangData = dragonFangData;
    }

    /*
     * Responsible for obtaining set of functions.
     */
    private Set<Entity> getFunctionEntitySet(Program program, AddressSetView asv,
                                             TaskMonitor monitor)
    {

        Set<Entity> functionSet = new HashSet<Entity>();

        FunctionIterator funcIter =
            program.getFunctionManager().getFunctionsNoStubs(asv, true);
        while (!monitor.isCancelled() && funcIter.hasNext()) {
            Function function = funcIter.next();
            FunctionEntity functionEntity = new FunctionEntity(function);
            functionSet.add(functionEntity);
        }

        return functionSet;
    }

    private VTMatchInfo createMatchInfo(VTMatchSet matchSet, Function sourceFunction,
                                        Function destinationFunction, VTScore similarity,
                                        VTScore confidence, VTMatchTag tag)
    {

        Address sourceAddress = sourceFunction.getEntryPoint();
        Address destinationAddress = destinationFunction.getEntryPoint();
        int sourceLength = (int) sourceFunction.getBody().getNumAddresses();
        int destinationLength = (int) destinationFunction.getBody().getNumAddresses();

        VTMatchInfo matchInfo = new VTMatchInfo(matchSet);
        matchInfo.setSimilarityScore(similarity);
        matchInfo.setConfidenceScore(confidence);
        matchInfo.setSourceLength(sourceLength);
        matchInfo.setDestinationLength(destinationLength);
        matchInfo.setSourceAddress(sourceAddress);
        matchInfo.setDestinationAddress(destinationAddress);
        matchInfo.setTag(tag);
        matchInfo.setAssociationType(VTAssociationType.FUNCTION);

        return matchInfo;
    }

    private void processNewMatches(Set<Match> foundMatches, VTMatchSet matchSet,
                                   Set<Entity> unmatchedSrcEntitySet,
                                   Set<Entity> unmatchedDstEntitySet,
                                   Queue<Match> propagationQueue)
    {

        for (Match match : foundMatches) {
            FunctionEntity srcEntity = (FunctionEntity) match.getSourceEntity();
            FunctionEntity dstEntity = (FunctionEntity) match.getDestinationEntity();
            double similarity = match.getSimilarityScore();
            double confidence = match.getConfidenceScore();
            String reason = match.getReason();

            unmatchedSrcEntitySet.remove(srcEntity);
            unmatchedDstEntitySet.remove(dstEntity);

            propagationQueue.add(match);

            VTMatchTag tag =
                dragonFangData.getMatchTagAssigner().assignTag(similarity, reason);
            VTMatchInfo matchInfo = createMatchInfo(
                matchSet, srcEntity.getFunction(), dstEntity.getFunction(),
                new VTScore(similarity), new VTScore(confidence), tag);
            matchSet.addMatch(matchInfo);
        }
    }

    @Override
    protected void doCorrelate(VTMatchSet matchSet, TaskMonitor monitor)
        throws CancelledException
    {

        monitor.setIndeterminate(false);

        // Get initial set of unmatched instructions.
        Set<Entity> unmatchedSrcEntitySet =
            getFunctionEntitySet(getSourceProgram(), getSourceAddressSet(), monitor);
        Set<Entity> unmatchedDstEntitySet = getFunctionEntitySet(
            getDestinationProgram(), getDestinationAddressSet(), monitor);

        boolean doPropagation = getOptions().getBoolean(
            DragonFangProgramCorrelatorFactory.PROPAGATION_STEP_OPT,
            DragonFangProgramCorrelatorFactory.PROPAGATION_STEP_DEFAULT);

        // Initialise Call Graphs.
        dragonFangData.getSourceCallGraphWrapper().init(monitor);
        dragonFangData.getDestinationCallGraphWrapper().init(monitor);

        List<Matcher> matchers = dragonFangData.getMatcherList();
        List<Propagator> propagators = dragonFangData.getPropagatorList();

        for (Matcher matcher : matchers) {
            Queue<Match> propagationQueue = new LinkedList<Match>();

            Set<Match> initialMatches =
                matcher.doMatch(unmatchedSrcEntitySet, unmatchedDstEntitySet, monitor);
            processNewMatches(initialMatches, matchSet, unmatchedSrcEntitySet,
                              unmatchedDstEntitySet, propagationQueue);

            if (doPropagation) {
                while (!propagationQueue.isEmpty() && !unmatchedSrcEntitySet.isEmpty()
                       && !unmatchedDstEntitySet.isEmpty()) {
                    Match match = propagationQueue.remove();

                    for (Propagator propagator : propagators) {
                        Set<Match> newMatches =
                            propagator.propagate(matcher, match, unmatchedSrcEntitySet,
                                                 unmatchedDstEntitySet, monitor);
                        processNewMatches(newMatches, matchSet, unmatchedSrcEntitySet,
                                          unmatchedDstEntitySet, propagationQueue);
                    }
                }
            }
        }
    }

    @Override
    public String getName()
    {

        return name;
    }
}
