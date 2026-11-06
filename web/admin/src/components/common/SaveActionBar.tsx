import React from 'react';
import { Button } from '@carbon/react';
import { Save, Renew, Information } from '@carbon/icons-react';

export interface SaveActionBarProps {
  isDirty: boolean;
  isSaving?: boolean;
  onReset: () => void;
  onSave: () => void | Promise<void>;
  saveLabel?: string;
  resetLabel?: string;
  message?: string;
  className?: string;
  style?: React.CSSProperties;
}

export const SaveActionBar: React.FC<SaveActionBarProps> = ({
  isDirty,
  isSaving = false,
  onReset,
  onSave,
  saveLabel = 'Save Changes',
  resetLabel = 'Reset',
  message = 'Careful — you have unsaved changes',
  className = '',
  style,
}) => {
  const visible = isDirty || isSaving;

  return (
    <div
      className={`operator-sticky-actions ${visible ? 'is-visible' : 'is-hidden'} ${className}`}
      data-save-action-bar="true"
      data-dirty={isDirty ? 'true' : 'false'}
      role="region"
      aria-label="Save changes"
      aria-hidden={!visible}
      style={style}
    >
      <div className="sticky-actions-info">
        <Information size={18} />
        <span>{message}</span>
      </div>
      <div className="section-save-actions">
        <Button
          kind="secondary"
          size="md"
          renderIcon={Renew}
          disabled={isSaving}
          onClick={onReset}
        >
          {resetLabel}
        </Button>
        <Button
          kind="primary"
          size="md"
          renderIcon={Save}
          disabled={isSaving}
          onClick={onSave}
        >
          {isSaving ? 'Saving...' : saveLabel}
        </Button>
      </div>
    </div>
  );
};