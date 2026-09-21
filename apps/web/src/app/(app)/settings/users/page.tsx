import { UsersView } from '@/components/settings/UsersView';

export const metadata = {
  title: 'Users',
};

export default function UsersPage() {
  return (
    <div className="p-6">
      <UsersView />
    </div>
  );
}
