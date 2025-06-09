import { useState } from 'react';
import { Form, InputGroup, Button } from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faEye, faEyeSlash, faLock } from '@fortawesome/free-solid-svg-icons';

const PasswordInput = ({
  value,
  onChange,
  name = 'password',
  placeholder = '請輸入密碼',
  label = '密碼',
  errors = [],
  required = true,
}) => {
  const [showPassword, setShowPassword] = useState(false);

  return (
    <Form.Group className="mb-4">
      <Form.Label>
        <FontAwesomeIcon icon={faLock} className="me-2" />
        {label}
      </Form.Label>
      <InputGroup>
        <Form.Control
          type={showPassword ? 'text' : 'password'}
          name={name}
          value={value}
          onChange={onChange}
          required={required}
          placeholder={placeholder}
          isInvalid={errors.length > 0}
        />
        <Button
          variant="outline-secondary"
          onClick={() => setShowPassword(!showPassword)}
          type="button"
        >
          <FontAwesomeIcon icon={showPassword ? faEyeSlash : faEye} />
        </Button>
      </InputGroup>
      {errors.length > 0 && (
        <div className="mt-1">
          {errors.map((error, index) => (
            <div key={index} className="text-danger fw-bold">
              {error}
            </div>
          ))}
        </div>
      )}
    </Form.Group>
  );
};

export default PasswordInput;
