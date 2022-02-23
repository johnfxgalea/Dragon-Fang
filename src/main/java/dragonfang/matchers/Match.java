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

package dragonfang.matchers;

import dragonfang.entities.Entity;

/**
 * Represents a one-to-one match result, mapping a source function and a
 * destination function.
 */
public class Match
{
    private Entity srcEntity;
    private Entity dstEntity;
    private double similarity;
    private double confidence;
    private String matcherName;
    private String propagatorName;

    public Match(Entity srcEntity, Entity dstEntity, double similarity, double confidence,
                 String matcherName)
    {

        this.srcEntity = srcEntity;
        this.dstEntity = dstEntity;
        this.similarity = similarity;
        this.confidence = confidence;
        this.matcherName = matcherName;
        this.propagatorName = "N/A";
    }

    /**
     *
     * @return The source entity of the match.
     */
    public Entity getSourceEntity()
    {
        return srcEntity;
    }

    /**
     *
     * @return The destination entity of the match.
     */
    public Entity getDestinationEntity()
    {
        return dstEntity;
    }

    /**
     *
     * @return The similarity of the match.
     */
    public double getSimilarityScore()
    {
        return similarity;
    }

    /**
     *
     * @return The confidence of the match.
     */
    public double getConfidenceScore()
    {
        return confidence;
    }

    public void setPropagatorName(String propagatorName)
    {
        this.propagatorName = propagatorName;
    }

    /**
     *
     * @return The reason of the match.
     */
    public String getReason()
    {
        if (propagatorName.equals(""))
            return matcherName;

        return matcherName + " - " + propagatorName;
    }
}
