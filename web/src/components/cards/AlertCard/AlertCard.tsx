/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import GenericItemCard from 'Components/GenericItemCard';
import { Flex, Icon, Link, Text, Box, BadgeProps } from 'pouncejs';
import { AlertTypesEnum } from 'Generated/schema';
import { Link as RRLink } from 'react-router-dom';
import SeverityBadge from 'Components/badges/SeverityBadge';
import React from 'react';
import urls from 'Source/urls';
import RelatedDestinations from 'Components/RelatedDestinations';
import BulletedTypeList from 'Components/BulletedTypeList';
import { AlertSummaryFull } from 'Source/graphql/fragments/AlertSummaryFull.generated';
import { formatDatetime } from 'Helpers/utils';
import useAlertDestinations from 'Hooks/useAlertDestinations';
import useAlertDestinationsDeliverySuccess from 'Hooks/useAlertDestinationsDeliverySuccess';
import { SelectCheckbox } from 'Components/utils/SelectContext';
import UpdateAlertDropdown from '../../dropdowns/UpdateAlertDropdown';

interface AlertCardProps {
  alert: AlertSummaryFull;
  hideRuleButton?: boolean;
  selectionEnabled?: boolean;
}

const ALERT_TYPE_COLOR_MAP: {
  [key in AlertCardProps['alert']['type']]: BadgeProps['color'];
} = {
  [AlertTypesEnum.Rule]: 'teal-500' as const,
  [AlertTypesEnum.RuleError]: 'red-300' as const,
  [AlertTypesEnum.Policy]: 'teal-200' as const,
};

const AlertCard: React.FC<AlertCardProps> = ({
  alert,
  hideRuleButton = false,
  selectionEnabled = false,
}) => {
  const { alertDestinations, loading: loadingDestinations } = useAlertDestinations({ alert });
  const { allDestinationDeliveredSuccessfully, loading } = useAlertDestinationsDeliverySuccess({
    alert,
  });

  const alertDetails = React.useMemo(() => {
    switch (alert.type) {
      case AlertTypesEnum.Rule:
        return {
          displayName: 'Rule Match',
          typesLabel: 'Log Types',
          label: 'Rule',
          ariaLabel: `Link to rule ${alert.ruleId}`,
          detailsLink: urls.logAnalysis.alerts.details(alert.alertId),
          detectionLink: urls.logAnalysis.rules.details(alert.ruleId),
        };
      case AlertTypesEnum.RuleError:
        return {
          displayName: 'Rule Error',
          typesLabel: 'Log Types',
          label: 'Rule',
          ariaLabel: `Link to rule ${alert.ruleId}`,
          detailsLink: urls.logAnalysis.alerts.details(alert.alertId),
          detectionLink: urls.logAnalysis.rules.details(alert.ruleId),
        };
      case AlertTypesEnum.Policy:
        return {
          displayName: 'Policy Fail',
          typesLabel: 'Resource Types',
          label: 'Policy',
          ariaLabel: `Link to policy ${alert.alertId}`,
          detailsLink: urls.logAnalysis.alerts.details(alert.alertId),
          detectionLink: urls.compliance.policies.details(alert.ruleId),
        };
      default:
        return {
          displayName: '',
          typesLabel: '',
          label: '',
          ariaLabel: '',
          detailsLink: '#',
          detectionLink: '#',
        };
    }
  }, [alert]);

  return (
    <GenericItemCard>
      <Flex align="start" pr={2}>
        {selectionEnabled && (
          <Box transform="translate3d(0,-8px,0)">
            <SelectCheckbox selectionId={alert.alertId} />
          </Box>
        )}
      </Flex>
      <GenericItemCard.Body>
        <GenericItemCard.Header>
          <GenericItemCard.Heading>
            <Link as={RRLink} aria-label="Link to Alert" to={alertDetails.detailsLink}>
              {alert.title}
            </Link>
          </GenericItemCard.Heading>
          <GenericItemCard.Date
            aria-label={`Creation time for ${alert.alertId}`}
            date={formatDatetime(alert.creationTime)}
          />
        </GenericItemCard.Header>
        <Text fontSize="small" as="span" color={ALERT_TYPE_COLOR_MAP[alert.type]}>
          {alertDetails.displayName}
        </Text>
        <GenericItemCard.ValuesGroup>
          {!hideRuleButton && (
            <GenericItemCard.Value
              label={alertDetails.label}
              value={
                <Flex spacing={2}>
                  <Text display="inline-flex" alignItems="center" as="span">
                    {alert.ruleId}
                  </Text>
                  <GenericItemCard.Link
                    aria-label={alertDetails.ariaLabel}
                    to={alertDetails.detectionLink}
                  />
                </Flex>
              }
            />
          )}
          <GenericItemCard.Value
            label="Destinations"
            value={
              <RelatedDestinations destinations={alertDestinations} loading={loadingDestinations} />
            }
          />
          <GenericItemCard.Value
            label={alertDetails.typesLabel}
            value={
              <BulletedTypeList types={[...alert.logTypes, ...alert.resourceTypes]} limit={2} />
            }
          />
          <GenericItemCard.Value
            label="Events"
            value={alert?.eventsMatched ? alert?.eventsMatched.toLocaleString() : '0'}
          />
          <Flex ml="auto" mr={0} align="flex-end" spacing={2}>
            <SeverityBadge severity={alert.severity} />
            <UpdateAlertDropdown alert={alert} />
          </Flex>
        </GenericItemCard.ValuesGroup>
        {!loading && !allDestinationDeliveredSuccessfully && (
          <Flex
            as="section"
            align="center"
            spacing={1}
            mt={2}
            aria-label="Destination delivery failure"
            fontStyle="italic"
            color="red-100"
            fontSize="small"
          >
            <Icon type="alert-circle-filled" size="medium" />
            <Text>
              There was an issue with the delivery of this alert to a selected destination.
            </Text>
            <RRLink to={alertDetails.detailsLink}>
              <Text textDecoration="underline">See details</Text>
            </RRLink>
          </Flex>
        )}
      </GenericItemCard.Body>
    </GenericItemCard>
  );
};

export default React.memo(AlertCard);
