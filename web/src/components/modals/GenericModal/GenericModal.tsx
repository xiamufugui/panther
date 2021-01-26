/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import React from 'react';
import { Modal, ModalProps } from 'pouncejs';

export interface GenericModalProps extends ModalProps {
  title: string;
  body: React.ReactNode;
}

const GenericModal: React.FC<GenericModalProps> = ({ body, ...rest }) => {
  return (
    <Modal showCloseButton {...rest}>
      {body}
    </Modal>
  );
};

export default GenericModal;
