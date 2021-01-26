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
import { AsanaConfig, SeverityEnum } from 'Generated/schema';
import AsanaDestinationForm from './index';

const emptyInitialValues = {
  outputId: null,
  displayName: '',
  defaultForSeverity: [],
  outputConfig: {
    asana: {
      personalAccessToken: '',
      projectGids: [],
    },
  },
};

const displayName = 'Asana';
const severity = SeverityEnum.Critical;

const gids = ['123', '456'];

const initialValues = {
  outputId: '123',
  displayName,
  outputConfig: {
    asana: {
      personalAccessToken: '',
      projectGids: ['123', '456'],
    },
  },
  defaultForSeverity: [severity],
};

describe('AsanaDestinationForm', () => {
  it('renders the correct fields', () => {
    const { getByLabelText, getByText } = render(
      <AsanaDestinationForm onSubmit={() => {}} initialValues={emptyInitialValues} />
    );
    const displayNameField = getByLabelText('* Display Name');
    const tokenField = getByLabelText('Access Token');
    const projectGidsField = getByLabelText('Project GIDs', { selector: 'input' });
    const submitButton = getByText('Add Destination');
    expect(displayNameField).toBeInTheDocument();
    expect(tokenField).toBeInTheDocument();
    expect(projectGidsField).toBeInTheDocument();
    Object.values(SeverityEnum).forEach(sev => {
      expect(getByText(sev)).toBeInTheDocument();
    });

    expect(submitButton).toHaveAttribute('disabled');
  });

  it('has proper validation', async () => {
    const { getByLabelText, getByText } = render(
      <AsanaDestinationForm onSubmit={() => {}} initialValues={emptyInitialValues} />
    );
    const displayNameField = getByLabelText('* Display Name');
    const tokenField = getByLabelText('Access Token');
    const projectGidsField = getByLabelText('Project GIDs', { selector: 'input' });
    const submitButton = getByText('Add Destination');
    const criticalSeverityCheckBox = document.getElementById(severity);
    expect(criticalSeverityCheckBox).not.toBeNull();
    expect(submitButton).toHaveAttribute('disabled');

    fireEvent.change(displayNameField, { target: { value: displayName } });
    fireEvent.click(criticalSeverityCheckBox);
    await waitMs(1);
    expect(submitButton).toHaveAttribute('disabled');
    fireEvent.change(tokenField, { target: { value: '123' } });
    await waitMs(1);
    expect(submitButton).toHaveAttribute('disabled');
    gids.forEach(gid => {
      fireEvent.change(projectGidsField, {
        target: {
          value: gid,
        },
      });
      fireEvent.blur(projectGidsField);
    });
    await waitMs(1);
    expect(submitButton).not.toHaveAttribute('disabled');
  });

  it('should trigger submit successfully', async () => {
    const submitMockFunc = jest.fn();
    const { getByLabelText, getByText } = render(
      <AsanaDestinationForm onSubmit={submitMockFunc} initialValues={emptyInitialValues} />
    );
    const displayNameField = getByLabelText('* Display Name');
    const tokenField = getByLabelText('Access Token');
    const projectGidsField = getByLabelText('Project GIDs', { selector: 'input' });
    const submitButton = getByText('Add Destination');
    const criticalSeverityCheckBox = document.getElementById(severity);
    expect(criticalSeverityCheckBox).not.toBeNull();
    expect(submitButton).toHaveAttribute('disabled');

    fireEvent.change(displayNameField, { target: { value: displayName } });
    fireEvent.click(criticalSeverityCheckBox);
    const token = '123';
    fireEvent.change(tokenField, { target: { value: token } });
    await waitMs(1);
    expect(submitButton).toHaveAttribute('disabled');
    gids.forEach(gid => {
      fireEvent.change(projectGidsField, {
        target: {
          value: gid,
        },
      });
      fireEvent.blur(projectGidsField);
    });
    await waitMs(1);
    expect(submitButton).not.toHaveAttribute('disabled');

    fireEvent.click(submitButton);
    await waitFor(() => expect(submitMockFunc).toHaveBeenCalledTimes(1));
    expect(submitMockFunc).toHaveBeenCalledWith({
      outputId: null,
      displayName,
      outputConfig: { asana: { personalAccessToken: token, projectGids: gids } as AsanaConfig },
      defaultForSeverity: [severity],
    });
  });

  it('should edit Asana Destination successfully', async () => {
    const submitMockFunc = jest.fn();
    const { getByLabelText, getByText } = render(
      <AsanaDestinationForm onSubmit={submitMockFunc} initialValues={initialValues} />
    );
    const displayNameField = getByLabelText('* Display Name');
    const submitButton = getByText('Update Destination');
    expect(displayNameField).toHaveValue(initialValues.displayName);
    expect(submitButton).toHaveAttribute('disabled');

    const newDisplayName = 'New Asana Name';
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
