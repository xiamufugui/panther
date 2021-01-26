/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import React from 'react';
import { render } from 'test-utils';
import GenericModal from './GenericModal';

const Body = () => <div>This is a body</div>;

describe('Generic modal component', () => {
  it('renders', async () => {
    const onClose = jest.fn();
    const { getByText, findByText, getByAriaLabel } = render(
      <GenericModal title={'Hello world'} body={<Body />} open onClose={onClose} />
    );
    await findByText('Hello world');
    expect(getByText('This is a body')).toBeTruthy();
    expect(getByAriaLabel('Dismiss Dialog')).toBeTruthy();
  });
});
