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

import React from 'react';
import { render, fireEvent, waitFor, waitMs } from 'test-utils';
import { OpsgenieServiceRegionEnum, SeverityEnum } from 'Generated/schema';
import OpsgenieDestinationForm from './index';

const emptyInitialValues = {
  outputId: null,
  displayName: '',
  defaultForSeverity: [],
  outputConfig: {
    opsgenie: {
      apiKey: '',
      serviceRegion: OpsgenieServiceRegionEnum.Us,
    },
  },
};

const displayName = 'Opsgenie';
const severity = SeverityEnum.Critical;

const initialValues = {
  outputId: '123',
  displayName,
  outputConfig: {
    opsgenie: {
      apiKey: '',
      serviceRegion: OpsgenieServiceRegionEnum.Us,
    },
  },

  defaultForSeverity: [severity],
};

describe('OpsGenieDestinationForm', () => {
  it('renders the correct fields', () => {
    const { getByLabelText, getByText } = render(
      <OpsgenieDestinationForm onSubmit={() => {}} initialValues={emptyInitialValues} />
    );
    const displayNameField = getByLabelText('* Display Name');
    const apiKeyField = getByLabelText('Opsgenie API key');
    const euServiceRegion = getByText('EU Service Region');
    const usServiceRegion = getByText('US Service Region');
    const submitButton = getByText('Add Destination');

    expect(displayNameField).toBeInTheDocument();
    expect(apiKeyField).toBeInTheDocument();
    expect(euServiceRegion).toBeInTheDocument();
    expect(usServiceRegion).toBeInTheDocument();
    Object.values(SeverityEnum).forEach(sev => {
      expect(getByText(sev)).toBeInTheDocument();
    });

    expect(submitButton).toHaveAttribute('disabled');
  });

  it('has proper validation', async () => {
    const { getByLabelText, getByText } = render(
      <OpsgenieDestinationForm onSubmit={() => {}} initialValues={emptyInitialValues} />
    );
    const displayNameField = getByLabelText('* Display Name');
    const apiKeyField = getByLabelText('Opsgenie API key');
    const submitButton = getByText('Add Destination');
    const criticalSeverityCheckBox = document.getElementById(severity);

    expect(submitButton).toHaveAttribute('disabled');

    fireEvent.change(displayNameField, { target: { value: displayName } });
    fireEvent.click(criticalSeverityCheckBox);

    await waitMs(1);

    expect(submitButton).toHaveAttribute('disabled');

    fireEvent.change(apiKeyField, { target: { value: '123' } });

    await waitMs(1);

    expect(submitButton).not.toHaveAttribute('disabled');
  });

  it('should trigger submit successfully', async () => {
    const submitMockFunc = jest.fn();
    const { getByLabelText, getByText } = render(
      <OpsgenieDestinationForm onSubmit={submitMockFunc} initialValues={emptyInitialValues} />
    );
    const displayNameField = getByLabelText('* Display Name');
    const euServiceRegion = getByLabelText('EU Service Region');
    const apiKeyField = getByLabelText('Opsgenie API key');
    const submitButton = getByText('Add Destination');
    const criticalSeverityCheckBox = document.getElementById(severity);
    expect(criticalSeverityCheckBox).not.toBeNull();
    expect(submitButton).toHaveAttribute('disabled');

    fireEvent.change(displayNameField, { target: { value: displayName } });
    fireEvent.change(apiKeyField, { target: { value: '123' } });
    fireEvent.click(euServiceRegion);
    fireEvent.click(criticalSeverityCheckBox);

    await waitMs(1);
    expect(submitButton).not.toHaveAttribute('disabled');

    fireEvent.click(submitButton);
    await waitFor(() => expect(submitMockFunc).toHaveBeenCalledTimes(1));

    expect(submitMockFunc).toHaveBeenCalledWith({
      outputId: null,
      displayName,
      outputConfig: { opsgenie: { apiKey: '123', serviceRegion: OpsgenieServiceRegionEnum.Eu } },
      defaultForSeverity: [severity],
    });
  });

  it('should edit Opsgenie Destination successfully', async () => {
    const submitMockFunc = jest.fn();
    const { getByLabelText, getByText } = render(
      <OpsgenieDestinationForm onSubmit={submitMockFunc} initialValues={initialValues} />
    );
    const displayNameField = getByLabelText('* Display Name');
    const submitButton = getByText('Update Destination');
    expect(displayNameField).toHaveValue(initialValues.displayName);
    expect(submitButton).toHaveAttribute('disabled');

    const newDisplayName = 'New Opsgenie Name';
    fireEvent.change(displayNameField, { target: { value: newDisplayName } });

    await waitMs(1);
    expect(submitButton).not.toHaveAttribute('disabled');

    fireEvent.click(submitButton);
    await waitFor(() => expect(submitMockFunc).toHaveBeenCalledTimes(1));
    expect(submitMockFunc).toHaveBeenCalledWith({
      outputId: initialValues.outputId,
      displayName: newDisplayName,
      outputConfig: initialValues.outputConfig,
      defaultForSeverity: initialValues.defaultForSeverity,
    });
  });
});
