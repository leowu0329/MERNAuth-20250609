import { Link, useNavigate } from 'react-router-dom';
import { Navbar, Nav, Container, Button, Modal } from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faUser, faSignOutAlt, faKey } from '@fortawesome/free-solid-svg-icons';
import { useAuth } from '../contexts/AuthContext';
import { toast } from 'react-toastify';
import { useState } from 'react';

const NavigationBar = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [showLogoutModal, setShowLogoutModal] = useState(false);

  const handleLogout = () => {
    logout();
    toast.success('登出成功');
    navigate('/login');
  };

  const handleResetPassword = () => {
    // 生成一個臨時的重設令牌
    const tempToken = 'temp-' + Date.now();
    navigate(`/reset-password/${tempToken}`);
  };

  return (
    <>
      <Navbar bg="white" expand="lg" className="shadow-sm py-2">
        <Container>
          <Navbar.Brand as={Link} to="/" className="fw-bold fs-6">
            Your Logo
          </Navbar.Brand>
          <Navbar.Toggle
            aria-controls="basic-navbar-nav"
            className="border-0"
          />
          <Navbar.Collapse id="basic-navbar-nav">
            <Nav className="ms-auto align-items-center">
              <Nav.Link
                as={Link}
                to="/profile"
                className="d-flex align-items-center py-1"
              >
                <FontAwesomeIcon icon={faUser} className="me-2" />
                {user?.name}
              </Nav.Link>
              <Nav.Link
                onClick={handleResetPassword}
                className="d-flex align-items-center py-1"
                style={{ cursor: 'pointer' }}
              >
                <FontAwesomeIcon icon={faKey} className="me-2" />
                重設密碼
              </Nav.Link>
              <Button
                variant="outline-primary"
                className="ms-2 py-1 px-3"
                onClick={() => setShowLogoutModal(true)}
                size="sm"
              >
                <FontAwesomeIcon icon={faSignOutAlt} className="me-2" />
                登出
              </Button>
            </Nav>
          </Navbar.Collapse>
        </Container>
      </Navbar>

      {/* 登出確認對話框 */}
      <Modal
        show={showLogoutModal}
        onHide={() => setShowLogoutModal(false)}
        centered
      >
        <Modal.Header closeButton>
          <Modal.Title>確認登出</Modal.Title>
        </Modal.Header>
        <Modal.Body>您確定要登出嗎？</Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowLogoutModal(false)}>
            取消
          </Button>
          <Button
            variant="primary"
            onClick={() => {
              setShowLogoutModal(false);
              handleLogout();
            }}
          >
            確認登出
          </Button>
        </Modal.Footer>
      </Modal>
    </>
  );
};

export default NavigationBar;
