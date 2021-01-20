import React from 'react';
import { buildDataModel, render } from 'test-utils';
import DataModelCard from './DataModelCard';

describe('DataModelCard', () => {
  it('matches snapshot', () => {
    const { container } = render(<DataModelCard dataModel={buildDataModel()} />);
    expect(container).toMatchSnapshot();
  });

  it('renders the necessary information', () => {
    const dataModel = buildDataModel();

    const { getByText, getByAriaLabel } = render(<DataModelCard dataModel={dataModel} />);

    expect(getByText(dataModel.id)).toBeInTheDocument();
    expect(getByText(dataModel.displayName)).toBeInTheDocument();
    expect(getByText(dataModel.enabled ? 'ENABLED' : 'DISABLED')).toBeInTheDocument();
    expect(getByAriaLabel('Toggle Options')).toBeInTheDocument();
  });

  it('fallbacks to `id` when display name is not existent', () => {
    const dataModel = buildDataModel({ displayName: '' });

    const { getAllByText } = render(<DataModelCard dataModel={dataModel} />);

    expect(getAllByText(dataModel.id)).toHaveLength(2);
  });
});
